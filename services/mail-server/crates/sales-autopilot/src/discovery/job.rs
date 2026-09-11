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

/// A discovery job as stored in `sales_discovery_jobs`.
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

/// Runs discovery jobs against a configured source set.
#[derive(Debug, Clone)]
pub struct DiscoveryJobRunner {
    db: PgPool,
    sources: Vec<Arc<dyn DiscoverySource>>,
}

impl DiscoveryJobRunner {
    pub fn new(db: PgPool, sources: Vec<Arc<dyn DiscoverySource>>) -> Self {
        Self { db, sources }
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
    /// `requested_sources` names the sources to run. Names that match no
    /// configured source are ignored; if none match, every configured source
    /// runs (a typo in a control-plane form must not silently disable
    /// discovery).
    pub async fn create_job(
        &self,
        tenant_id: &str,
        query: &DiscoveryQuery,
        requested_sources: &[String],
    ) -> Result<DiscoveryJob, SalesError> {
        let selected = self.select_sources(requested_sources);
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
        let sources = self.sources_for_job(&job);
        if sources.is_empty() {
            return Err(SalesError::InvalidInput(
                "no discovery sources are configured".into(),
            ));
        }
        let max_pages = max_pages_per_source.max(1);

        sqlx::query(
            "UPDATE sales_discovery_jobs
             SET status = 'running', started_at = COALESCE(started_at, NOW())
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(job_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

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
                    source.as_ref(),
                    &query,
                    &mut state,
                    max_pages,
                )
                .await;
            if batch.status == "succeeded" {
                succeeded += 1;
            } else if let Some(error) = &batch.error {
                error_messages.push(format!("{}: {error}", source.id()));
            }
            new_total += batch.new_candidates;
            self.insert_source_run(tenant_id, job_id, source.id(), &batch)
                .await?;
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

        sqlx::query(
            "UPDATE sales_discovery_jobs SET
                status = $3,
                cursor = $4,
                discovered = discovered + $5,
                cost_eur = (
                    SELECT COALESCE(SUM(cost_eur), 0)::float8::numeric
                    FROM sales_source_runs WHERE job_id = $1
                ),
                error = $6,
                completed_at = $7
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(job_id)
        .bind(tenant_id)
        .bind(status)
        .bind(state.to_json())
        .bind(new_total)
        .bind(&job_error)
        .bind(completed_at)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        self.load_job(tenant_id, job_id).await
    }

    /// Run batches until the job completes, fails or is cancelled.
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

    async fn load_job(&self, tenant_id: &str, job_id: Uuid) -> Result<DiscoveryJob, SalesError> {
        let job: Option<DiscoveryJob> = sqlx::query_as(
            "SELECT id, tenant_id, query, sources, status, cursor, discovered, imported,
                    cost_eur::float8 AS cost_eur, error, created_at, started_at, completed_at
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

    fn select_sources(&self, requested: &[String]) -> Vec<Arc<dyn DiscoverySource>> {
        if requested.is_empty() {
            return self.sources.clone();
        }
        let selected: Vec<Arc<dyn DiscoverySource>> = self
            .sources
            .iter()
            .filter(|source| requested.iter().any(|name| name == source.id()))
            .cloned()
            .collect();
        if selected.is_empty() {
            self.sources.clone()
        } else {
            selected
        }
    }

    fn sources_for_job(&self, job: &DiscoveryJob) -> Vec<Arc<dyn DiscoverySource>> {
        self.select_sources(&job.sources)
    }

    async fn run_source_batch(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        source: &dyn DiscoverySource,
        query: &DiscoveryQuery,
        state: &mut CursorState,
        max_pages: usize,
    ) -> SourceBatch {
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
                        match upsert_candidate(&self.db, tenant_id, job_id, source.id(), candidate)
                            .await
                        {
                            Ok(true) => new_candidates += 1,
                            Ok(false) => {}
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

        SourceBatch {
            status,
            http_status: source.last_http_status(),
            items,
            new_candidates,
            cost_eur,
            latency_ms: started.elapsed().as_millis() as i64,
            error,
        }
    }

    async fn insert_source_run(
        &self,
        tenant_id: &str,
        job_id: Uuid,
        source_id: &str,
        batch: &SourceBatch,
    ) -> Result<(), SalesError> {
        sqlx::query(
            "INSERT INTO sales_source_runs (
                id, tenant_id, job_id, source, status, http_status, items,
                cost_eur, latency_ms, error, started_at, completed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::float8::numeric, $9, $10, NOW(), NOW())",
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
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }
}

/// Upsert one candidate. Returns `true` when a fresh row was inserted,
/// `false` when an existing `(tenant, source, source_url)` row was refreshed.
async fn upsert_candidate(
    db: &PgPool,
    tenant_id: &str,
    job_id: Uuid,
    source: &str,
    candidate: &DiscoveredCandidate,
) -> Result<bool, SalesError> {
    let domain = sanitize_domain(candidate.domain.as_deref());
    let source_url = sanitize_source_url(candidate.source_url.as_deref());
    let company_name = sanitize_company_name(candidate.company_name.as_deref());
    let jurisdiction = sanitize_jurisdiction(candidate.jurisdiction.as_deref());
    let hash = sanitize_snapshot_hash(candidate.raw_snapshot_hash.as_deref());
    let confidence = clamp_confidence(candidate.confidence);
    let jurisdiction_confidence = clamp_confidence(candidate.jurisdiction_confidence);
    let refresh_expires_at = Utc::now() + chrono::Duration::days(REFRESH_TTL_DAYS);

    let inserted: bool = sqlx::query_scalar(
        "INSERT INTO sales_discovery_candidates (
            id, tenant_id, job_id, source, source_url, company_name, account_domain,
            jurisdiction, jurisdiction_confidence, raw_snapshot_hash, confidence,
            refresh_expires_at, discovered_at, created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
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
    .fetch_one(db)
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
}
