//! Discovery job runner: persistence, dedupe, jurisdiction control and
//! promotion.
//!
//! # Persistence map
//!
//! | step | table | columns |
//! |------|-------|---------|
//! | command | `sales_discovery_jobs` | query, sources, status, cursor, discovered, imported, cost_eur, error, timestamps |
//! | per source per run | `sales_source_runs` | source, status, http_status, items, cost_eur, latency_ms, error |
//! | per candidate | `sales_discovery_candidates` | source, source_url, company_name, account_domain, jurisdiction, jurisdiction_confidence, raw_snapshot_hash, confidence, refresh_expires_at, discovered_at |
//!
//! Candidates are upserted against the partial unique index
//! `idx_sales_discovery_candidates_source_url` on
//! `(tenant_id, source, source_url) WHERE source_url IS NOT NULL`
//! (`200_sales_autopilot_v2_unification.sql:882-884`), and only *fresh
//! inserts* increment `sales_discovery_jobs.discovered` — a re-run of the
//! same query does not double-count.
//!
//! All values coming back from a provider are sanitized before they touch the
//! database ([`sanitize_domain`], [`sanitize_source_url`],
//! [`sanitize_snapshot_hash`], [`sanitize_company_name`],
//! [`sanitize_jurisdiction`], [`clamp_confidence`]): a hostile provider
//! cannot write a 4 KB domain, an empty "hash", a `javascript:` URL or an
//! out-of-range confidence.
//!
//! # Lease protocol (audit item 14)
//!
//! `sales_discovery_jobs` carries `lease_owner`, `lease_token`,
//! `lease_expires_at` and `attempt` (migration
//! `201_sales_execution_contract.sql:123-139`). One `run_job` batch is one
//! claim:
//!
//! 1. **Claim** — a single conditional `UPDATE ... WHERE status IN
//!    ('queued','running') AND (lease_expires_at IS NULL OR lease_expires_at
//!    < NOW())` issues a fresh `lease_token`. Postgres serialises concurrent
//!    claims on the row, so exactly one runner wins and the losers get a
//!    distinct [`JOB_LEASED_MARKER`] outcome without calling any provider.
//! 2. **Fence** — every cursor/terminal write carries the token
//!    (`WHERE ... AND lease_token = $token`), and source-run/candidate writes
//!    are scoped through an `EXISTS (... lease_token = $token)` guard because
//!    `sales_source_runs` has no token column (`200:886-900`). A runner whose
//!    lease was superseded by a recovery claim writes zero rows and stops, so
//!    a recovered job's stale runner cannot append runs or advance the
//!    cursor.
//! 3. **Heartbeat** — the lease is extended before every (possibly slow)
//!    provider call. The lease is released when the batch finishes (any
//!    status), so `run_to_completion` can reclaim its own job for the next
//!    batch without waiting out the lease.
//! 4. **Attempt ceiling** — a job whose runner keeps crashing is recovered
//!    with `attempt + 1`; past [`MAX_JOB_ATTEMPTS`] consecutive claims
//!    without progress the job is failed instead of retried forever. A batch
//!    that reaches `running`/`completed` resets the counter; a `failed` batch
//!    keeps it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::provider::{
    candidate_allowed_by_jurisdiction, DiscoveredCandidate, DiscoveryQuery, DiscoverySource,
};
use crate::types::SalesError;

/// Maximum candidates accepted from one provider page (defence in depth: a
/// provider returning 10 000 candidates is truncated, not trusted).
pub const MAX_CANDIDATES_PER_PAGE: usize = 1_000;
/// Maximum provider pages fetched per source per `run_job` batch.
pub const MAX_PAGES_PER_RUN: usize = 3;
/// Hard bound on `run_to_completion` batches.
pub const MAX_BATCHES: usize = 100;
/// How long a discovered candidate stays fresh before re-discovery.
pub const REFRESH_TTL_DAYS: i64 = 30;

/// How long one runner owns a claimed job. The lease is extended
/// (heartbeat) before every provider call; when it lapses — a crashed
/// runner — another runner may claim the job.
pub const JOB_LEASE_MINUTES: i64 = 5;

/// Consecutive claims without progress after which a job is failed instead
/// of being recovered again. A crash-looping runner never writes the
/// progress update, so its claims accumulate; any batch that reaches
/// `running`/`completed` resets the counter ([`DiscoveryJobRunner::run_job`]).
pub const MAX_JOB_ATTEMPTS: i32 = 5;

/// Marker prefix on the [`SalesError::ServiceUnavailable`] message returned
/// when a claim loses the race (another runner owns the job, or the job
/// changed to a terminal state). Callers can match this stable prefix to
/// distinguish "owned elsewhere, retry later" from a transient failure.
pub const JOB_LEASED_MARKER: &str = "discovery_job_leased";

/// A discovery job as stored in `sales_discovery_jobs`.
///
/// `lease_token` is deliberately NOT part of this public shape: it is a
/// capability the runner keeps private.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryJob {
    pub id: Uuid,
    pub tenant_id: String,
    pub query: serde_json::Value,
    pub sources: Vec<String>,
    pub status: String,
    pub cursor: Option<String>,
    pub discovered: i64,
    pub imported: i64,
    pub cost_eur: f64,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Diagnostic owner label of the current lease (the token is the fence).
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// Claims since the last progressing batch; see [`MAX_JOB_ATTEMPTS`].
    pub attempt: i32,
}

/// Per-source outcome of one `run_job` batch.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRunReport {
    pub source: String,
    pub status: String,
    pub http_status: Option<i32>,
    pub items: i64,
    pub new_candidates: i64,
    pub dropped_jurisdiction: i64,
    pub cost_eur: f64,
    pub latency_ms: i64,
    pub error: Option<String>,
}

/// Full report of one `run_job` batch.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRunReport {
    pub job: DiscoveryJob,
    pub source_runs: Vec<SourceRunReport>,
}

/// Cursor state persisted in `sales_discovery_jobs.cursor` as JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CursorState {
    /// source id → next cursor (source has more pages).
    cursors: BTreeMap<String, String>,
    /// source ids whose pagination is exhausted.
    done: BTreeSet<String>,
}

impl CursorState {
    fn parse(raw: Option<&str>) -> Self {
        raw.and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default()
    }

    fn to_json(&self) -> Option<String> {
        if self.cursors.is_empty() && self.done.is_empty() {
            None
        } else {
            serde_json::to_string(self).ok()
        }
    }
}

struct SourceBatch {
    status: &'static str,
    http_status: Option<i32>,
    items: i64,
    new_candidates: i64,
    cost_eur: f64,
    latency_ms: i64,
    error: Option<String>,
}

/// The result of an atomic claim: the job now owned by this runner plus the
/// fencing token every later write must carry.
struct ClaimedJob {
    job: DiscoveryJob,
    lease_token: Uuid,
}

/// Row shape of the claim's explicit `RETURNING` list: the [`DiscoveryJob`]
/// columns plus the token.
///
/// `RETURNING *` is not used because `cost_eur` is NUMERIC and sqlx does not
/// decode NUMERIC into `f64`; the claim casts it exactly like [`DiscoveryJobRunner::load_job`].
#[derive(sqlx::FromRow)]
struct ClaimedJobRow {
    #[sqlx(flatten)]
    job: DiscoveryJob,
    lease_token: Uuid,
}

/// Requested source names that match no configured source id, first-seen
/// order and de-duplicated.
fn unknown_source_names(configured: &[&str], requested: &[String]) -> Vec<String> {
    let mut unknown: Vec<String> = Vec::new();
    for name in requested {
        if !configured.iter().any(|id| *id == name.as_str())
            && !unknown.iter().any(|seen| seen == name)
        {
            unknown.push(name.clone());
        }
    }
    unknown
}

/// The distinct, documented outcome of a claim that lost the race: another
/// runner owns the job (or it turned terminal between load and claim). The
/// stable [`JOB_LEASED_MARKER`] prefix lets callers distinguish it from a
/// transient failure.
fn job_leased_error(job_id: Uuid, current: &DiscoveryJob) -> SalesError {
    let until = current
        .lease_expires_at
        .map(|expires| expires.to_rfc3339())
        .unwrap_or_else(|| "unknown".to_string());
    SalesError::ServiceUnavailable(format!(
        "{JOB_LEASED_MARKER}: discovery job {job_id} is owned by {} and not claimable until \
         {until}; no provider was called",
        current.lease_owner.as_deref().unwrap_or("another runner"),
    ))
}

/// The distinct, documented outcome of losing an owned lease mid-batch: the
/// token was superseded (a recovery claim) or expired. The runner stopped
/// without writing; the recovered owner finishes the job.
fn lease_lost_error(job_id: Uuid) -> SalesError {
    SalesError::ServiceUnavailable(format!(
        "{JOB_LEASED_MARKER}: discovery job {job_id} lease lost (superseded or expired); \
         this runner stopped without writing and the current owner will finish the job"
    ))
}

/// Runs discovery jobs against a configured source set.
#[derive(Debug, Clone)]
pub struct DiscoveryJobRunner {
    db: PgPool,
    sources: Vec<Arc<dyn DiscoverySource>>,
    /// Diagnostic `lease_owner` label. The random per-claim `lease_token`,
    /// not this label, is the actual fence.
    runner_id: String,
}

impl DiscoveryJobRunner {
    pub fn new(db: PgPool, sources: Vec<Arc<dyn DiscoverySource>>) -> Self {
        Self {
            db,
            sources,
            runner_id: format!("discovery-runner-{}", Uuid::new_v4().simple()),
        }
    }

    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// Ids of every configured source.
    pub fn source_ids(&self) -> Vec<&'static str> {
        self.sources.iter().map(|source| source.id()).collect()
    }

    /// Insert a job in `queued` status.
    ///
    /// `requested_sources` names the sources to run. An empty request means
    /// every configured source. A name that matches no configured source is
    /// [`SalesError::InvalidInput`] — the old fallback to "all configured
    /// sources" is deleted (audit item 14): running a possibly paid provider
    /// because of a typo is not acceptable. The error names every unknown
    /// source.
    pub async fn create_job(
        &self,
        tenant_id: &str,
        query: &DiscoveryQuery,
        requested_sources: &[String],
    ) -> Result<DiscoveryJob, SalesError> {
        let selected = self.select_sources(requested_sources)?;
        let source_ids: Vec<String> = selected
            .iter()
            .map(|source| source.id().to_string())
            .collect();
        let query_json = serde_json::to_value(query)
            .map_err(|error| SalesError::Internal(anyhow::anyhow!(error)))?;

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_discovery_jobs (id, tenant_id, query, sources, status)
             VALUES ($1, $2, $3, $4, 'queued')",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&query_json)
        .bind(&source_ids)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        self.load_job(tenant_id, id).await
    }

    /// Load one job, tenant-scoped.
    pub async fn get_job(&self, tenant_id: &str, job_id: Uuid) -> Result<DiscoveryJob, SalesError> {
        self.load_job(tenant_id, job_id).await
    }

    /// Execute one batch: up to [`MAX_PAGES_PER_RUN`] pages per not-yet-done
    /// source, resuming from the persisted cursor. Terminal jobs are refused.
    ///
    /// The batch claims the job first; a job leased by another runner is a
    /// distinct [`SalesError::ServiceUnavailable`] carrying
    /// [`JOB_LEASED_MARKER`], and no provider is called. Every write the batch
    /// makes is fenced by the claim's token, so two runners racing for one job
    /// call the provider exactly once per logical page.
    pub async fn run_job(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        max_pages_per_source: usize,
    ) -> Result<DiscoveryJob, SalesError> {
        let job = self.load_job(tenant_id, job_id).await?;
        if matches!(job.status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(SalesError::InvalidInput(format!(
                "discovery job {job_id} is already {}",
                job.status
            )));
        }
        // Resolve (and validate) the source set BEFORE claiming: an unknown
        // configured name must fail without holding the job and without
        // touching any provider.
        let sources = self.sources_for_job(&job)?;
        if sources.is_empty() {
            return Err(SalesError::InvalidInput(
                "no discovery sources are configured".into(),
            ));
        }
        let max_pages = max_pages_per_source.max(1);

        // Atomic claim. `None` means another runner owns the job (or it
        // became terminal between the load and the claim).
        let Some(claim) = self.claim_job(tenant_id, job_id).await? else {
            let current = self.load_job(tenant_id, job_id).await?;
            if matches!(
                current.status.as_str(),
                "completed" | "failed" | "cancelled"
            ) {
                return Err(SalesError::InvalidInput(format!(
                    "discovery job {job_id} is already {}",
                    current.status
                )));
            }
            return Err(job_leased_error(job_id, &current));
        };
        let lease_token = claim.lease_token;
        let job = claim.job;

        // Attempt ceiling: a job whose lease keeps expiring (a runner that
        // crashes every batch) must not be recovered forever. A batch that
        // reaches running/completed resets `attempt`, so only consecutive
        // claims without progress count.
        if job.attempt > MAX_JOB_ATTEMPTS {
            self.fail_at_attempt_ceiling(tenant_id, job_id, lease_token)
                .await?;
            return Err(SalesError::ServiceUnavailable(format!(
                "discovery job {job_id} exceeded its attempt ceiling of {MAX_JOB_ATTEMPTS} \
                 consecutive claims without progress and was marked failed"
            )));
        }

        let mut state = CursorState::parse(job.cursor.as_deref());
        let query: DiscoveryQuery = serde_json::from_value(job.query.clone()).unwrap_or_default();

        let mut attempted = 0usize;
        let mut succeeded = 0usize;
        let mut new_total = 0i64;
        let mut error_messages: Vec<String> = Vec::new();

        for source in &sources {
            if state.done.contains(source.id()) {
                continue;
            }
            attempted += 1;
            let batch = self
                .run_source_batch(
                    tenant_id,
                    job_id,
                    lease_token,
                    source.as_ref(),
                    &query,
                    &mut state,
                    max_pages,
                )
                .await?;
            if batch.status == "succeeded" {
                succeeded += 1;
            } else if let Some(error) = &batch.error {
                error_messages.push(format!("{}: {error}", source.id()));
            }
            new_total += batch.new_candidates;
            if !self
                .insert_source_run(tenant_id, job_id, lease_token, source.id(), &batch)
                .await?
            {
                // The lease was superseded before this run could be recorded;
                // write nothing further and let the recovery runner own it.
                return Err(lease_lost_error(job_id));
            }
        }

        let all_done = sources
            .iter()
            .all(|source| state.done.contains(source.id()));
        let (status, job_error, completed_at) = if attempted > 0 && succeeded == 0 {
            (
                "failed",
                Some(format!(
                    "every discovery source failed: {}",
                    error_messages.join("; ")
                )),
                Some(Utc::now()),
            )
        } else if all_done {
            ("completed", None, Some(Utc::now()))
        } else {
            ("running", None, None)
        };

        self.finish_batch(
            tenant_id,
            job_id,
            lease_token,
            status,
            state.to_json(),
            new_total,
            job_error.as_deref(),
            completed_at,
        )
        .await?;

        self.load_job(tenant_id, job_id).await
    }

    /// Run batches until the job completes, fails or is cancelled.
    ///
    /// A lease lost to a concurrent runner surfaces as [`SalesError`]: this
    /// runner cannot know whether the other runner completed the job, and
    /// silently reporting the other runner's state as its own outcome would
    /// hide the contention. Callers retry (the job is claimable again once
    /// the other lease is released or expires).
    pub async fn run_to_completion(
        &self,
        tenant_id: &str,
        job_id: Uuid,
    ) -> Result<DiscoveryJob, SalesError> {
        let mut job = self.load_job(tenant_id, job_id).await?;
        if matches!(job.status.as_str(), "completed" | "failed" | "cancelled") {
            return Ok(job);
        }
        for _ in 0..MAX_BATCHES {
            job = self.run_job(tenant_id, job_id, MAX_PAGES_PER_RUN).await?;
            if job.status != "running" {
                break;
            }
        }
        Ok(job)
    }

    /// Atomically claim a job for this runner.
    ///
    /// One conditional UPDATE is the entire ownership test: Postgres takes a
    /// row lock, re-evaluates the predicate after the winner commits, and
    /// returns no row for the losers. Only `queued`/`running` jobs with no
    /// live lease are claimable, so a crashed runner's expired lease makes
    /// the job recoverable and a live lease blocks everyone else.
    async fn claim_job(
        &self,
        tenant_id: &str,
        job_id: Uuid,
    ) -> Result<Option<ClaimedJob>, SalesError> {
        let claimed: Option<ClaimedJobRow> = sqlx::query_as(
            "UPDATE sales_discovery_jobs
             SET status = 'running',
                 lease_owner = $3,
                 lease_token = gen_random_uuid(),
                 lease_expires_at = NOW() + make_interval(mins => $4::int),
                 attempt = attempt + 1,
                 started_at = COALESCE(started_at, NOW())
             WHERE id = $1 AND tenant_id = $2
               AND status IN ('queued','running')
               AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
             RETURNING id, tenant_id, query, sources, status, cursor, discovered, imported,
                       cost_eur::float8 AS cost_eur, error, created_at, started_at,
                       completed_at, lease_owner, lease_expires_at, attempt, lease_token",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(&self.runner_id)
        .bind(JOB_LEASE_MINUTES as i32)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        Ok(claimed.map(|row| ClaimedJob {
            job: row.job,
            lease_token: row.lease_token,
        }))
    }

    /// Renew the lease while a (possibly slow) provider request is in flight.
    ///
    /// `false` means the token no longer owns the job — it was superseded by
    /// a recovery claim or the lease already expired. The caller must stop
    /// without writing anything.
    async fn heartbeat(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_discovery_jobs
             SET lease_expires_at = NOW() + make_interval(mins => $4::int)
             WHERE id = $1 AND tenant_id = $2 AND lease_token = $3 AND status = 'running'",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(lease_token)
        .bind(JOB_LEASE_MINUTES as i32)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .rows_affected();

        Ok(affected == 1)
    }

    /// Persist the batch outcome, fenced by the lease token, and release the
    /// lease so the next batch (or another runner) can claim the job.
    ///
    /// A token mismatch updates zero rows and is [`SalesError`]: the stale
    /// runner must not advance the cursor or write a terminal status.
    /// `attempt` resets on `running`/`completed` (progress was made) and is
    /// kept on `failed` so repeated failed recoveries hit the ceiling.
    async fn finish_batch(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        lease_token: Uuid,
        status: &str,
        cursor: Option<String>,
        new_total: i64,
        job_error: Option<&str>,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<(), SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_discovery_jobs SET
                status = $3,
                cursor = $4,
                discovered = discovered + $5,
                cost_eur = (
                    SELECT COALESCE(SUM(cost_eur), 0)::float8::numeric
                    FROM sales_source_runs WHERE job_id = $1
                ),
                error = $6,
                completed_at = $7,
                attempt = CASE WHEN $3::text = 'failed' THEN attempt ELSE 0 END,
                lease_owner = NULL,
                lease_token = NULL,
                lease_expires_at = NULL
             WHERE id = $1 AND tenant_id = $2 AND lease_token = $8",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(status)
        .bind(cursor)
        .bind(new_total)
        .bind(job_error)
        .bind(completed_at)
        .bind(lease_token)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .rows_affected();

        if affected == 0 {
            return Err(lease_lost_error(job_id));
        }
        Ok(())
    }

    /// Fail a job that exhausted [`MAX_JOB_ATTEMPTS`], fenced by the token.
    async fn fail_at_attempt_ceiling(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        lease_token: Uuid,
    ) -> Result<(), SalesError> {
        sqlx::query(
            "UPDATE sales_discovery_jobs
             SET status = 'failed',
                 error = $3,
                 completed_at = NOW(),
                 lease_owner = NULL,
                 lease_token = NULL,
                 lease_expires_at = NULL
             WHERE id = $1 AND tenant_id = $2 AND lease_token = $4",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(format!(
            "attempt ceiling exceeded ({MAX_JOB_ATTEMPTS} consecutive claims without progress); \
             refusing to retry forever"
        ))
        .bind(lease_token)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }

    async fn load_job(&self, tenant_id: &str, job_id: Uuid) -> Result<DiscoveryJob, SalesError> {
        let job: Option<DiscoveryJob> = sqlx::query_as(
            "SELECT id, tenant_id, query, sources, status, cursor, discovered, imported,
                    cost_eur::float8 AS cost_eur, error, created_at, started_at, completed_at,
                    lease_owner, lease_expires_at, attempt
             FROM sales_discovery_jobs
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(job_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        job.ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "discovery job {job_id} not found for tenant {tenant_id}"
            ))
        })
    }

    /// Match the requested source names against the configured sources.
    ///
    /// * empty request → every configured source;
    /// * any requested name that matches nothing → [`SalesError::InvalidInput`]
    ///   naming every unknown source. Deliberately NO fallback to all
    ///   configured providers: a typo must not spend money on a paid API.
    fn select_sources(
        &self,
        requested: &[String],
    ) -> Result<Vec<Arc<dyn DiscoverySource>>, SalesError> {
        if requested.is_empty() {
            return Ok(self.sources.clone());
        }
        let configured: Vec<&'static str> = self.sources.iter().map(|source| source.id()).collect();
        let unknown = unknown_source_names(&configured, requested);
        if !unknown.is_empty() {
            return Err(SalesError::InvalidInput(format!(
                "unknown discovery source(s): {}",
                unknown.join(", ")
            )));
        }

        let mut selected: Vec<Arc<dyn DiscoverySource>> = Vec::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for name in requested {
            if !seen.insert(name.as_str()) {
                continue;
            }
            if let Some(source) = self.sources.iter().find(|source| source.id() == name) {
                selected.push(source.clone());
            }
        }
        Ok(selected)
    }

    fn sources_for_job(
        &self,
        job: &DiscoveryJob,
    ) -> Result<Vec<Arc<dyn DiscoverySource>>, SalesError> {
        self.select_sources(&job.sources)
    }

    async fn run_source_batch(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        lease_token: Uuid,
        source: &dyn DiscoverySource,
        query: &DiscoveryQuery,
        state: &mut CursorState,
        max_pages: usize,
    ) -> Result<SourceBatch, SalesError> {
        let started = Instant::now();
        let mut cursor = state.cursors.get(source.id()).cloned();
        let mut pages = 0usize;
        let mut items = 0i64;
        let mut new_candidates = 0i64;
        let mut dropped_jurisdiction = 0i64;
        let mut cost_eur = 0.0f64;
        let mut error: Option<String> = None;
        let mut status: &'static str = "succeeded";

        while pages < max_pages {
            // Heartbeat BEFORE the provider call: the request may be slow,
            // and the lease must cover it. A lost lease aborts the batch
            // before any further write.
            if !self.heartbeat(tenant_id, job_id, lease_token).await? {
                return Err(lease_lost_error(job_id));
            }

            match source.discover(query, cursor.as_deref()).await {
                Ok(page) => {
                    pages += 1;
                    items += page.candidates.len() as i64;
                    if page.cost_eur.is_finite() && page.cost_eur > 0.0 {
                        cost_eur += page.cost_eur;
                    }

                    let allowed = source.allowed_jurisdictions();
                    let mut candidates: Vec<DiscoveredCandidate> = Vec::new();
                    for candidate in page.candidates.into_iter().take(MAX_CANDIDATES_PER_PAGE) {
                        if candidate_allowed_by_jurisdiction(
                            allowed,
                            candidate.jurisdiction.as_deref(),
                        ) {
                            candidates.push(candidate);
                        } else {
                            dropped_jurisdiction += 1;
                        }
                    }

                    for candidate in &candidates {
                        match upsert_candidate(
                            &self.db,
                            tenant_id,
                            job_id,
                            lease_token,
                            source.id(),
                            candidate,
                        )
                        .await
                        {
                            Ok(Some(true)) => new_candidates += 1,
                            Ok(Some(false)) => {}
                            // Zero rows means the token no longer owns the
                            // job: the candidate write was refused, and the
                            // whole batch must stop without other writes.
                            Ok(None) => return Err(lease_lost_error(job_id)),
                            Err(db_error) => {
                                status = "failed";
                                error = Some(format!("candidate persistence failed: {db_error}"));
                                break;
                            }
                        }
                    }
                    if status != "succeeded" {
                        break;
                    }

                    match page.next_cursor {
                        Some(next) if !next.trim().is_empty() => {
                            cursor = Some(next);
                        }
                        _ => {
                            cursor = None;
                            state.done.insert(source.id().to_string());
                            break;
                        }
                    }
                }
                Err(discovery_error) => {
                    status = discovery_error.run_status();
                    error = Some(discovery_error.to_string());
                    break;
                }
            }
        }

        if status == "succeeded" {
            match &cursor {
                Some(next) => {
                    state.cursors.insert(source.id().to_string(), next.clone());
                }
                None => {
                    state.cursors.remove(source.id());
                }
            }
        }

        // The jurisdiction drop is a real control and must be visible in the
        // run record. `sales_source_runs` has no dedicated counter column, so
        // the note is carried in `error` while the status stays accurate.
        if dropped_jurisdiction > 0 {
            let note = format!(
                "jurisdiction_filter: dropped {dropped_jurisdiction} candidate(s) outside permitted jurisdictions [{}]",
                source.allowed_jurisdictions().join(", ")
            );
            error = match error {
                Some(existing) => Some(format!("{existing}; {note}")),
                None => Some(note),
            };
        }

        Ok(SourceBatch {
            status,
            http_status: source.last_http_status(),
            items,
            new_candidates,
            cost_eur,
            latency_ms: started.elapsed().as_millis() as i64,
            error,
        })
    }

    /// Persist one source-run row, fenced by the job's live lease.
    ///
    /// `sales_source_runs` has no lease-token column (`200:886-900`), so the
    /// write is scoped THROUGH the job row: the `INSERT ... SELECT` only
    /// produces a row while `sales_discovery_jobs.lease_token` still equals
    /// this runner's token. A superseded runner inserts zero rows — returning
    /// `false` — and `run_job` aborts, so a recovered job's stale runner can
    /// never append runs.
    async fn insert_source_run(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        lease_token: Uuid,
        source_id: &str,
        batch: &SourceBatch,
    ) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "INSERT INTO sales_source_runs (
                id, tenant_id, job_id, source, status, http_status, items,
                cost_eur, latency_ms, error, started_at, completed_at
             )
             SELECT $1, $2, $3, $4, $5, $6, $7, $8::float8::numeric, $9, $10, NOW(), NOW()
             WHERE EXISTS (
                 SELECT 1 FROM sales_discovery_jobs
                 WHERE id = $3 AND tenant_id = $2 AND lease_token = $11
             )",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(job_id)
        .bind(source_id)
        .bind(batch.status)
        .bind(batch.http_status)
        .bind(batch.items)
        .bind(batch.cost_eur)
        .bind(batch.latency_ms)
        .bind(&batch.error)
        .bind(lease_token)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .rows_affected();

        Ok(affected == 1)
    }
}

/// Upsert one candidate, fenced by the job's live lease.
///
/// Returns `Some(true)` when a fresh row was inserted, `Some(false)` when an
/// existing `(tenant, source, source_url)` row was refreshed, and `None` when
/// the lease token no longer owns the job (the write was refused; the caller
/// must abort without writing anything else). The fence is the same
/// `EXISTS (... lease_token = $token)` guard as [`DiscoveryJobRunner::insert_source_run`]
/// because `sales_discovery_candidates` has no token column either.
async fn upsert_candidate(
    db: &PgPool,
    tenant_id: &str,
    job_id: Uuid,
    lease_token: Uuid,
    source: &str,
    candidate: &DiscoveredCandidate,
) -> Result<Option<bool>, SalesError> {
    let domain = sanitize_domain(candidate.domain.as_deref());
    let source_url = sanitize_source_url(candidate.source_url.as_deref());
    let company_name = sanitize_company_name(candidate.company_name.as_deref());
    let jurisdiction = sanitize_jurisdiction(candidate.jurisdiction.as_deref());
    let hash = sanitize_snapshot_hash(candidate.raw_snapshot_hash.as_deref());
    let confidence = clamp_confidence(candidate.confidence);
    let jurisdiction_confidence = clamp_confidence(candidate.jurisdiction_confidence);
    let refresh_expires_at = Utc::now() + chrono::Duration::days(REFRESH_TTL_DAYS);

    let inserted: Option<bool> = sqlx::query_scalar(
        "INSERT INTO sales_discovery_candidates (
            id, tenant_id, job_id, source, source_url, company_name, account_domain,
            jurisdiction, jurisdiction_confidence, raw_snapshot_hash, confidence,
            refresh_expires_at, discovered_at, created_at
         )
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW()
         WHERE EXISTS (
             SELECT 1 FROM sales_discovery_jobs
             WHERE id = $3 AND tenant_id = $2 AND lease_token = $13
         )
         ON CONFLICT (tenant_id, source, source_url) WHERE source_url IS NOT NULL
         DO UPDATE SET
            company_name = COALESCE(EXCLUDED.company_name, sales_discovery_candidates.company_name),
            account_domain = COALESCE(EXCLUDED.account_domain, sales_discovery_candidates.account_domain),
            jurisdiction = COALESCE(EXCLUDED.jurisdiction, sales_discovery_candidates.jurisdiction),
            jurisdiction_confidence = GREATEST(
                sales_discovery_candidates.jurisdiction_confidence,
                EXCLUDED.jurisdiction_confidence
            ),
            raw_snapshot_hash = EXCLUDED.raw_snapshot_hash,
            confidence = GREATEST(sales_discovery_candidates.confidence, EXCLUDED.confidence),
            refresh_expires_at = EXCLUDED.refresh_expires_at
         RETURNING (xmax = 0) AS inserted",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(job_id)
    .bind(source)
    .bind(&source_url)
    .bind(&company_name)
    .bind(&domain)
    .bind(&jurisdiction)
    .bind(jurisdiction_confidence)
    .bind(&hash)
    .bind(confidence)
    .bind(refresh_expires_at)
    .bind(lease_token)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    Ok(inserted)
}

// ---------------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------------

/// Promote a discovery candidate into the canonical account model.
///
/// * Refuses (with a precise reason) when the candidate has no usable domain
///   or does not exist for the tenant.
/// * `ON CONFLICT (tenant_id, domain) DO UPDATE SET updated_at = NOW()` —
///   the canonical account row is immutable through this path, so promoting
///   the same candidate twice (or two candidates with the same domain)
///   yields exactly one `sales_accounts` row.
/// * Counts `sales_discovery_jobs.imported` only on the first promotion.
pub async fn promote_candidate(
    db: &PgPool,
    tenant_id: &str,
    candidate_id: Uuid,
) -> Result<Uuid, SalesError> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let row: Option<(
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT account_domain, promoted_account_id, job_id, company_name, jurisdiction
             FROM sales_discovery_candidates
             WHERE id = $1 AND tenant_id = $2
             FOR UPDATE",
    )
    .bind(candidate_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let Some((raw_domain, already_promoted, job_id, company_name, jurisdiction)) = row else {
        return Err(SalesError::InvalidInput(format!(
            "discovery candidate {candidate_id} not found for tenant {tenant_id}"
        )));
    };

    // Idempotent: already promoted → return the same account, no double count.
    if let Some(account_id) = already_promoted {
        tx.commit()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        return Ok(account_id);
    }

    let Some(domain) = sanitize_domain(raw_domain.as_deref()) else {
        return Err(SalesError::InvalidInput(format!(
            "discovery candidate {candidate_id} has no usable domain — promotion refused"
        )));
    };

    let company = sanitize_company_name(company_name.as_deref()).unwrap_or_else(|| domain.clone());
    let country = sanitize_jurisdiction(jurisdiction.as_deref());

    let account_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_accounts (id, tenant_id, company, domain, country, lifecycle, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'discovered', NOW(), NOW())
         ON CONFLICT (tenant_id, domain) DO UPDATE SET updated_at = NOW()
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(&company)
    .bind(&domain)
    .bind(&country)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    sqlx::query(
        "UPDATE sales_discovery_candidates
         SET promoted_account_id = $3
         WHERE id = $1 AND tenant_id = $2 AND promoted_account_id IS NULL",
    )
    .bind(candidate_id)
    .bind(tenant_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    if let Some(job_id) = job_id {
        sqlx::query(
            "UPDATE sales_discovery_jobs SET imported = imported + 1
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(job_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(account_id)
}

// ---------------------------------------------------------------------------
// Sanitizers (pure, unit-tested)
// ---------------------------------------------------------------------------

const MAX_URL_LEN: usize = 2_048;
const MAX_HASH_LEN: usize = 128;
const MAX_COMPANY_NAME_CHARS: usize = 1_024;
const MAX_JURISDICTION_LEN: usize = 64;

/// Normalize a candidate domain.
///
/// Accepts a bare hostname or an absolute URL (host extracted), requires at
/// least two labels, rejects oversized/empty/invalid hostnames.
pub fn sanitize_domain(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let candidate = if raw.contains("://") {
        url::Url::parse(raw).ok()?.host_str()?.to_string()
    } else {
        raw.to_string()
    };
    let candidate = candidate.trim().trim_end_matches('.').to_ascii_lowercase();
    if candidate.is_empty() || candidate.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = candidate.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }
    Some(candidate)
}

/// Normalize a candidate source URL. Only `http`/`https` and the internal
/// `first-party` scheme are accepted; anything else (including
/// `javascript:`) is dropped to `NULL`.
pub fn sanitize_source_url(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() || raw.len() > MAX_URL_LEN {
        return None;
    }
    let parsed = url::Url::parse(raw).ok()?;
    match parsed.scheme() {
        "http" | "https" | "first-party" => {
            if parsed.host_str().is_none() {
                return None;
            }
        }
        _ => return None,
    }
    Some(raw.to_string())
}

/// Normalize a raw snapshot hash; empty, oversized or control-character
/// values become `None` rather than a fake hash.
pub fn sanitize_snapshot_hash(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() || raw.len() > MAX_HASH_LEN {
        return None;
    }
    if raw.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        Some(raw.to_string())
    } else {
        None
    }
}

/// Normalize a jurisdiction code/name; control characters and oversized
/// values become `None`.
pub fn sanitize_jurisdiction(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() || raw.len() > MAX_JURISDICTION_LEN {
        return None;
    }
    if raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.')
    {
        Some(raw.to_string())
    } else {
        None
    }
}

/// Normalize a company name, truncating absurd values at a char boundary.
pub fn sanitize_company_name(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let mut out: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_COMPANY_NAME_CHARS)
        .collect();
    while out.ends_with(' ') {
        out.pop();
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Clamp a provider-reported confidence into `[0, 1]` (`NaN → 0`).
pub fn clamp_confidence(value: f32) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        f64::from(value).clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_domain_accepts_real_domains_and_urls() {
        assert_eq!(
            sanitize_domain(Some("Acme.EE.")),
            Some("acme.ee".to_string())
        );
        assert_eq!(
            sanitize_domain(Some("https://www.acme.ee/path?q=1")),
            Some("www.acme.ee".to_string())
        );
        assert_eq!(
            sanitize_domain(Some("acme-fintech.co.uk")),
            Some("acme-fintech.co.uk".to_string())
        );
    }

    #[test]
    fn sanitize_domain_rejects_hostile_input() {
        assert_eq!(sanitize_domain(None), None);
        assert_eq!(sanitize_domain(Some("")), None);
        assert_eq!(sanitize_domain(Some("   ")), None);
        // 4 KB domain string.
        assert_eq!(sanitize_domain(Some(&"a".repeat(4_096))), None);
        // Single label.
        assert_eq!(sanitize_domain(Some("localhost")), None);
        // Spaces / control characters.
        assert_eq!(sanitize_domain(Some("evil domain.com")), None);
        assert_eq!(sanitize_domain(Some("evil\u{0}.com")), None);
        // Over-long label.
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(sanitize_domain(Some(&long_label)), None);
    }

    #[test]
    fn sanitize_source_url_only_allows_approved_schemes() {
        assert_eq!(
            sanitize_source_url(Some("https://registry.example/company/1")),
            Some("https://registry.example/company/1".to_string())
        );
        assert_eq!(
            sanitize_source_url(Some("first-party://account/abc")),
            Some("first-party://account/abc".to_string())
        );
        assert_eq!(sanitize_source_url(Some("not a url")), None);
        assert_eq!(sanitize_source_url(Some("javascript:alert(1)")), None);
        assert_eq!(sanitize_source_url(Some("")), None);
        assert_eq!(
            sanitize_source_url(Some(&format!("https://x.example/{}", "a".repeat(4_096)))),
            None
        );
    }

    #[test]
    fn sanitize_snapshot_hash_rejects_empty_and_oversized() {
        assert_eq!(sanitize_snapshot_hash(Some("")), None);
        assert_eq!(sanitize_snapshot_hash(Some("  ")), None);
        assert_eq!(
            sanitize_snapshot_hash(Some("abc123")),
            Some("abc123".into())
        );
        assert_eq!(sanitize_snapshot_hash(Some(&"f".repeat(256))), None);
        assert_eq!(sanitize_snapshot_hash(Some("bad\u{7}hash")), None);
    }

    #[test]
    fn clamp_confidence_bounds() {
        assert_eq!(clamp_confidence(f32::NAN), 0.0);
        assert_eq!(clamp_confidence(-2.0), 0.0);
        assert_eq!(clamp_confidence(0.75), 0.75);
        assert_eq!(clamp_confidence(9.0), 1.0);
    }

    #[test]
    fn sanitize_company_name_truncates_at_char_boundary() {
        let long = "ü".repeat(5_000);
        let sanitized = sanitize_company_name(Some(&long)).expect("non-empty");
        assert_eq!(sanitized.chars().count(), MAX_COMPANY_NAME_CHARS);
        assert_eq!(sanitize_company_name(Some("  ")), None);
        assert_eq!(sanitize_company_name(Some("  Acme  ")), Some("Acme".into()));
    }

    #[test]
    fn sanitize_jurisdiction_rejects_control_characters() {
        assert_eq!(sanitize_jurisdiction(Some("EE")), Some("EE".into()));
        assert_eq!(sanitize_jurisdiction(Some("  ")), None);
        assert_eq!(sanitize_jurisdiction(Some("E\nE")), None);
        assert_eq!(sanitize_jurisdiction(Some(&"E".repeat(100))), None);
    }

    #[test]
    fn cursor_state_round_trips_and_corrupt_values_are_default() {
        let mut state = CursorState::default();
        state.cursors.insert("provider_api".into(), "page-2".into());
        state.done.insert("first_party".into());
        let raw = state.to_json().expect("non-empty state");
        let parsed = CursorState::parse(Some(&raw));
        assert_eq!(parsed.cursors.get("provider_api"), Some(&"page-2".into()));
        assert!(parsed.done.contains("first_party"));

        assert_eq!(CursorState::parse(Some("{not json")).cursors.len(), 0);
        assert_eq!(CursorState::parse(None).done.len(), 0);
        assert!(CursorState::default().to_json().is_none());
    }

    // -----------------------------------------------------------------------
    // Lease / ownership tests (audit item 14)
    //
    // These follow the crate's canonical bootstrap
    // (`test_db::canonical_test_pool`) and SOFT-SKIP with no test database,
    // so they run for real wherever `SALES_TEST_DATABASE_URL` points at the
    // canonical schema.
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::discovery::provider::{DiscoveryError, DiscoveryPage};

    /// A provider that counts every `discover` call, so a test can prove how
    /// many times the provider was actually invoked.
    #[derive(Debug)]
    struct RecordingSource {
        id: &'static str,
        calls: Arc<AtomicUsize>,
        candidates: Vec<DiscoveredCandidate>,
        page_size: usize,
        delay: Option<Duration>,
    }

    impl RecordingSource {
        fn new(id: &'static str, calls: Arc<AtomicUsize>) -> Self {
            Self {
                id,
                calls,
                candidates: Vec::new(),
                page_size: 100,
                delay: None,
            }
        }

        fn with_candidates(
            id: &'static str,
            calls: Arc<AtomicUsize>,
            candidates: Vec<DiscoveredCandidate>,
        ) -> Self {
            Self {
                id,
                calls,
                candidates,
                page_size: 100,
                delay: None,
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = Some(delay);
            self
        }
    }

    #[async_trait::async_trait]
    impl DiscoverySource for RecordingSource {
        fn id(&self) -> &'static str {
            self.id
        }

        fn allowed_jurisdictions(&self) -> &[&'static str] {
            &[]
        }

        async fn discover(
            &self,
            _query: &DiscoveryQuery,
            cursor: Option<&str>,
        ) -> Result<DiscoveryPage, DiscoveryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            let offset: usize = cursor
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
                .min(self.candidates.len());
            let end = (offset + self.page_size).min(self.candidates.len());
            Ok(DiscoveryPage {
                candidates: self.candidates[offset..end].to_vec(),
                next_cursor: (end < self.candidates.len()).then(|| end.to_string()),
                cost_eur: 0.0,
            })
        }
    }

    fn recording_candidate(url: &str, domain: &str) -> DiscoveredCandidate {
        DiscoveredCandidate {
            source: String::new(),
            source_url: Some(url.to_string()),
            company_name: Some(format!("Recording {domain}")),
            domain: Some(domain.to_string()),
            jurisdiction: Some("US".to_string()),
            jurisdiction_confidence: 0.9,
            confidence: 0.9,
            raw_snapshot_hash: None,
        }
    }

    fn lazy_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool")
    }

    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    async fn cleanup_discovery(pool: &PgPool, tenant: &str) {
        for statement in [
            "DELETE FROM sales_discovery_candidates WHERE tenant_id = $1",
            "DELETE FROM sales_source_runs WHERE tenant_id = $1",
            "DELETE FROM sales_discovery_jobs WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn select_sources_rejects_unknown_names_without_falling_back() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source: Arc<dyn DiscoverySource> =
            Arc::new(RecordingSource::new("known_fixture", calls.clone()));
        let runner = DiscoveryJobRunner::new(lazy_pool(), vec![source]);

        let error = runner
            .select_sources(&["typo_fixture".to_string()])
            .expect_err("an entirely unrecognized request must error");
        assert!(matches!(error, SalesError::InvalidInput(_)));
        assert_eq!(
            error.to_string(),
            "invalid input: unknown discovery source(s): typo_fixture"
        );

        // A mixed request is also rejected, naming only the unknown names.
        let error = runner
            .select_sources(&["known_fixture".to_string(), "other_typo".to_string()])
            .expect_err("a partially unknown request must error");
        assert!(error.to_string().contains("other_typo"));
        assert!(!error.to_string().contains("known_fixture"));

        // No provider was called and the empty request still selects all
        // configured sources (the legitimate default).
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(runner.select_sources(&[]).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unknown_requested_source_errors_before_any_provider_call() {
        let Some(pool) = live_pool("unknown_source").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("unknown-src");
        let calls = Arc::new(AtomicUsize::new(0));
        let source: Arc<dyn DiscoverySource> =
            Arc::new(RecordingSource::new("configured_fixture", calls.clone()));
        let runner = DiscoveryJobRunner::new(pool.clone(), vec![source]);

        let error = runner
            .create_job(
                &tenant,
                &DiscoveryQuery::default(),
                &["not_configured".to_string()],
            )
            .await
            .expect_err("an unrecognized requested source must not create a job");
        assert!(matches!(error, SalesError::InvalidInput(_)));
        assert!(error
            .to_string()
            .contains("unknown discovery source(s): not_configured"));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no provider may be called");

        let jobs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_discovery_jobs WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(jobs, 0, "the rejected request must not leave a job behind");

        cleanup_discovery(&pool, &tenant).await;
    }

    /// Two runners race for one job: exactly one claim wins, and the provider
    /// is called exactly once per logical page (one page here).
    #[tokio::test]
    async fn concurrent_run_job_claims_once_and_calls_provider_once_per_page() {
        let Some(pool) = live_pool("lease_concurrency").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("disc-lease");
        let calls = Arc::new(AtomicUsize::new(0));
        let source: Arc<dyn DiscoverySource> = Arc::new(
            RecordingSource::with_candidates(
                "lease_fixture",
                calls.clone(),
                vec![
                    recording_candidate("https://recording.example/a", "rec-a.example"),
                    recording_candidate("https://recording.example/b", "rec-b.example"),
                ],
            )
            // The provider is slow enough that the loser's claim definitely
            // arrives while the winner holds the lease.
            .with_delay(Duration::from_millis(200)),
        );
        let runner_a = DiscoveryJobRunner::new(pool.clone(), vec![source.clone()]);
        let runner_b = DiscoveryJobRunner::new(pool.clone(), vec![source.clone()]);
        let job = runner_a
            .create_job(
                &tenant,
                &DiscoveryQuery::default(),
                &["lease_fixture".to_string()],
            )
            .await
            .expect("create job");

        let (first, second) = tokio::join!(
            runner_a.run_job(&tenant, job.id, 1),
            runner_b.run_job(&tenant, job.id, 1)
        );
        let wins = [first.is_ok(), second.is_ok()]
            .into_iter()
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1, "exactly one runner may claim the job");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the provider must be called once per logical page, not once per runner"
        );

        let loser = [&first, &second]
            .into_iter()
            .find_map(|result| result.as_ref().err())
            .expect("one runner must lose the race");
        assert!(matches!(loser, SalesError::ServiceUnavailable(_)));
        assert!(
            loser.to_string().contains(JOB_LEASED_MARKER),
            "the loser must get the documented leased outcome, got: {loser}"
        );

        let finished = runner_a.get_job(&tenant, job.id).await.unwrap();
        assert_eq!(finished.status, "completed");
        let runs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_source_runs WHERE tenant_id = $1 AND job_id = $2",
        )
        .bind(&tenant)
        .bind(job.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(runs, 1, "one source-run row for the one executed page");

        cleanup_discovery(&pool, &tenant).await;
    }

    /// A runner whose token was superseded cannot append source runs, advance
    /// the cursor, or write a terminal status.
    #[tokio::test]
    async fn stale_runner_cannot_advance_cursor_or_write_terminal_status() {
        let Some(pool) = live_pool("stale_runner").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("stale-runner");
        let calls = Arc::new(AtomicUsize::new(0));
        let source: Arc<dyn DiscoverySource> =
            Arc::new(RecordingSource::new("stale_fixture", calls.clone()));
        let runner = DiscoveryJobRunner::new(pool.clone(), vec![source]);
        let job = runner
            .create_job(
                &tenant,
                &DiscoveryQuery::default(),
                &["stale_fixture".to_string()],
            )
            .await
            .expect("create job");

        // Runner 1 claims, then "crashes": force the lease into the past.
        let first = runner
            .claim_job(&tenant, job.id)
            .await
            .unwrap()
            .expect("first claim");
        sqlx::query(
            "UPDATE sales_discovery_jobs SET lease_expires_at = NOW() - INTERVAL '1 minute' \
             WHERE id = $1",
        )
        .bind(job.id)
        .execute(&pool)
        .await
        .unwrap();
        let second = runner
            .claim_job(&tenant, job.id)
            .await
            .unwrap()
            .expect("recovery claim");
        assert_ne!(first.lease_token, second.lease_token);

        // The stale runner cannot heartbeat, append a source run, or finish.
        assert!(
            !runner
                .heartbeat(&tenant, job.id, first.lease_token)
                .await
                .unwrap(),
            "the superseded token must not renew the lease"
        );
        let batch = SourceBatch {
            status: "succeeded",
            http_status: None,
            items: 1,
            new_candidates: 0,
            cost_eur: 0.0,
            latency_ms: 1,
            error: None,
        };
        assert!(
            !runner
                .insert_source_run(&tenant, job.id, first.lease_token, "stale_fixture", &batch)
                .await
                .unwrap(),
            "the stale runner must not append source runs"
        );
        let stale_finish = runner
            .finish_batch(
                &tenant,
                job.id,
                first.lease_token,
                "completed",
                Some("{\"done\":[]}".to_string()),
                1,
                None,
                Some(Utc::now()),
            )
            .await;
        assert!(
            stale_finish.is_err(),
            "stale terminal write must be refused"
        );

        // Nothing changed: no run row, no cursor, still running and owned by
        // the recovery claim.
        let current = runner.get_job(&tenant, job.id).await.unwrap();
        assert_eq!(current.status, "running");
        assert!(
            current.cursor.is_none(),
            "the stale cursor must not advance"
        );
        let runs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_source_runs WHERE tenant_id = $1 AND job_id = $2",
        )
        .bind(&tenant)
        .bind(job.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(runs, 0);

        // The recovery claim still owns the job and can finish it.
        assert!(runner
            .finish_batch(
                &tenant,
                job.id,
                second.lease_token,
                "completed",
                None,
                0,
                None,
                Some(Utc::now()),
            )
            .await
            .is_ok());
        assert_eq!(
            runner.get_job(&tenant, job.id).await.unwrap().status,
            "completed"
        );

        cleanup_discovery(&pool, &tenant).await;
    }

    /// A job whose runner crashed (expired lease, status `running`) is
    /// claimable again and completes.
    #[tokio::test]
    async fn expired_lease_is_recovered_and_the_job_completes() {
        let Some(pool) = live_pool("expired_lease").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("expired-lease");
        let calls = Arc::new(AtomicUsize::new(0));
        let source: Arc<dyn DiscoverySource> = Arc::new(RecordingSource::with_candidates(
            "recover_fixture",
            calls.clone(),
            vec![recording_candidate(
                "https://recording.example/recover",
                "recover.example",
            )],
        ));
        let runner = DiscoveryJobRunner::new(pool.clone(), vec![source]);
        let job = runner
            .create_job(
                &tenant,
                &DiscoveryQuery::default(),
                &["recover_fixture".to_string()],
            )
            .await
            .expect("create job");

        // The crashed runner's leftover: running, owned by a dead label, with
        // an expired lease and one attempt already spent.
        sqlx::query(
            "UPDATE sales_discovery_jobs SET status = 'running', lease_owner = 'crashed-runner', \
                 lease_token = gen_random_uuid(), \
                 lease_expires_at = NOW() - INTERVAL '1 minute', attempt = 1 \
             WHERE id = $1",
        )
        .bind(job.id)
        .execute(&pool)
        .await
        .unwrap();

        let finished = runner
            .run_to_completion(&tenant, job.id)
            .await
            .expect("the expired lease must be recoverable");
        assert_eq!(finished.status, "completed");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one logical page, one call"
        );

        let attempt: i32 =
            sqlx::query_scalar("SELECT attempt FROM sales_discovery_jobs WHERE id = $1")
                .bind(job.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(attempt, 0, "progress resets the crash counter");

        cleanup_discovery(&pool, &tenant).await;
    }

    /// A permanently crashing job is failed at the attempt ceiling instead of
    /// being recovered forever; no provider is called for the poisoned claim.
    #[tokio::test]
    async fn attempt_ceiling_fails_a_crash_looping_job() {
        let Some(pool) = live_pool("attempt_ceiling").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("ceiling");
        let calls = Arc::new(AtomicUsize::new(0));
        let source: Arc<dyn DiscoverySource> =
            Arc::new(RecordingSource::new("ceiling_fixture", calls.clone()));
        let runner = DiscoveryJobRunner::new(pool.clone(), vec![source]);
        let job = runner
            .create_job(
                &tenant,
                &DiscoveryQuery::default(),
                &["ceiling_fixture".to_string()],
            )
            .await
            .expect("create job");

        // MAX_JOB_ATTEMPTS recovery claims were already spent without progress.
        sqlx::query(
            "UPDATE sales_discovery_jobs SET status = 'running', \
                 lease_token = gen_random_uuid(), \
                 lease_expires_at = NOW() - INTERVAL '1 minute', attempt = $2 \
             WHERE id = $1",
        )
        .bind(job.id)
        .bind(MAX_JOB_ATTEMPTS)
        .execute(&pool)
        .await
        .unwrap();

        let error = runner
            .run_job(&tenant, job.id, 1)
            .await
            .expect_err("the ceiling claim must fail the job");
        assert!(error.to_string().contains("attempt ceiling"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no provider call past the ceiling"
        );

        let job_row = runner.get_job(&tenant, job.id).await.unwrap();
        assert_eq!(job_row.status, "failed");
        assert!(job_row
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("attempt ceiling"));

        cleanup_discovery(&pool, &tenant).await;
    }
}
