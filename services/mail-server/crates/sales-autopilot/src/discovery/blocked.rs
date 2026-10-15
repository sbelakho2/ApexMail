//! Blocked-source queue, persistent host health, and the audited solver hook.
//!
//! This module is the operator-facing half of the CAPTCHA story. The fetch
//! layer ([`super::fetch`]) classifies a response deterministically and
//! refuses to hand a blocked body to a parser; this module makes the block
//! *visible, reviewable and auditable*:
//!
//! ```text
//! ScrapeClient::fetch ──► FetchError::Blocked{…} ──► BlockedEvidence
//!                                                        │
//!                          DiscoveryJobRunner ───────────┤ (job + lease fenced)
//!                                                        ▼
//!                                    sales_scrape_blocked_sources   (queue)
//!                                    sales_scrape_host_health        (backoff,
//!                                                                     solver opt-in)
//! ```
//!
//! # The solver hook — disabled by default, opt-in per host
//!
//! `SCRAPE_CAPTCHA_SOLVER_URL` (+ optional `SCRAPE_CAPTCHA_SOLVER_TOKEN`)
//! names an operator-run challenge-solving service. Three independent gates
//! must ALL be open before a single byte leaves the process:
//!
//! 1. **The hook is configured.** Environment-only: no database row, admin
//!    route, job payload or request body can point the engine at a solver.
//!    With the variable unset, [`attempt_solve`] writes an audit row with
//!    outcome `disabled` and performs no HTTP request at all.
//! 2. **The host is opted in.** `sales_scrape_host_health.solver_enabled` is
//!    set by an operator through the admin route, per host. A host that is
//!    merely blocked is NOT opted in.
//! 3. **No backoff window is active.** A host inside its backoff is refused
//!    (`backoff_active`), and the single retry after a successful solve goes
//!    through the ordinary fetch policy: robots, politeness and the backoff
//!    gate all still apply. Nothing bypasses the per-host backoff.
//!
//! Every attempt — including the ones refused by gate 1, 2 or 3 — writes a
//! `sales_scrape_solver_audit` row. Cookie/token material is never stored or
//! logged; the audit records only *that* a token was received and what the
//! one retry did.
//!
//! # The solver wire contract
//!
//! The hook POSTs JSON to `SCRAPE_CAPTCHA_SOLVER_URL` (with
//! `Authorization: Bearer <SCRAPE_CAPTCHA_SOLVER_TOKEN>` when the token is
//! set) and refuses redirects, so the token cannot travel to another origin.
//! The response is read with a `SCRAPE_CAPTCHA_SOLVER_TIMEOUT_MS` timeout and
//! a 64 KiB cap.
//!
//! Request:
//!
//! ```json
//! { "url": "https://register.example/company/1",
//!   "host": "register.example",
//!   "source": "public_web",
//!   "classification": "blocked_captcha",
//!   "http_status": 403,
//!   "markers": ["cloudflare:__cf_chl_opt"],
//!   "detail": "challenge kinds: cloudflare",
//!   "first_seen_at": "2026-10-15T20:00:00Z",
//!   "user_agent": "ApexMail/1.0 (…)",
//!   "operator": "operator@apexmail.ee" }
//! ```
//!
//! Response (HTTP 200):
//!
//! ```json
//! { "status": "solved",
//!   "cookie": "cf_clearance=…",           // optional
//!   "headers": {"X-Solver-Token": "…"},   // optional, same host only
//!   "detail": "…" }                       // optional
//! ```
//!
//! `status` is `solved` or `failed`. A `solved` answer MUST carry retry
//! material (`cookie` and/or `headers`); both are validated against CR/LF
//! injection and length caps before they are sent, and they are applied to
//! exactly one same-host retry. Any other shape — a non-2xx, a timeout, an
//! oversized body, JSON without `status` — is [`SolverOutcome::SolverFailed`]
//! and backs the host off.
//!
//! # What this module deliberately does NOT do
//!
//! There is no built-in solver, no bundled bypass, no "just retry with a
//! browser UA", no captcha-farm integration, and no robots override. The
//! hook is a seam for an operator's own lawful service; the engine never
//! pretends to defeat a challenge on its own.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::fetch::{BlockedEvidence, FetchClassification, ScrapeClient};
use crate::types::SalesError;

/// Queue states. Owned here (the migration is deliberately CHECK-free so a
/// future state does not need a schema change).
pub const BLOCKED_STATE_OPEN: &str = "open";
pub const BLOCKED_STATE_SOLVED: &str = "solved";
pub const BLOCKED_STATE_DISMISSED: &str = "dismissed";

/// One row of the blocked-source review queue.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct BlockedSource {
    pub id: Uuid,
    pub tenant_id: String,
    pub source: String,
    pub url: String,
    pub host: String,
    pub classification: String,
    pub http_status: Option<i32>,
    pub markers: Vec<String>,
    pub detail: Option<String>,
    pub retry_after: Option<DateTime<Utc>>,
    pub occurrences: i64,
    pub state: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub last_job_id: Option<Uuid>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_note: Option<String>,
}

/// One row of `sales_scrape_host_health`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct HostHealthRow {
    pub host: String,
    pub consecutive_blocks: i32,
    pub total_blocks: i64,
    pub last_classification: Option<String>,
    pub last_status: Option<i32>,
    pub last_blocked_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub blocked_until: Option<DateTime<Utc>>,
    pub solver_enabled: bool,
    pub solver_enabled_at: Option<DateTime<Utc>>,
    pub solver_enabled_by: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Fencing for queue writes made from inside a leased discovery job: a
/// superseded runner must not append blocked-source evidence (same protocol
/// as [`super::job`]'s run and candidate writes).
#[derive(Debug, Clone, Copy)]
pub struct LeaseFence {
    pub job_id: Uuid,
    pub lease_token: Uuid,
}

/// Upsert one blocked fetch into the review queue, fenced by the job lease
/// when there is one.
///
/// Returns `Some(id)` with the queue row's id, or `None` when the fence was
/// supplied and no longer owns the job (the write was refused — the caller
/// must stop, exactly like the run/candidate writes).
///
/// Re-observation is the same row: occurrences increment, the latest
/// classification/status/markers replace the old ones, and a row an operator
/// had closed REOPENS (new evidence must not stay hidden behind an old
/// acknowledgement; the review note is kept as history).
pub async fn record_blocked_fetch(
    db: &PgPool,
    tenant_id: &str,
    source: &str,
    fence: Option<LeaseFence>,
    blocked: &BlockedEvidence,
) -> Result<Option<Uuid>, SalesError> {
    let (job_id, lease_token) = match fence {
        Some(fence) => (Some(fence.job_id), Some(fence.lease_token)),
        None => (None, None),
    };
    let retry_after = blocked
        .retry_after_seconds
        .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds as i64));

    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO sales_scrape_blocked_sources (
            id, tenant_id, source, url, host, classification, http_status,
            markers, detail, retry_after, occurrences, state,
            first_seen_at, last_seen_at, last_job_id
         )
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, 'open', NOW(), NOW(), $11
         WHERE $12::uuid IS NULL
            OR EXISTS (
                SELECT 1 FROM sales_discovery_jobs
                WHERE id = $12 AND tenant_id = $2 AND lease_token = $13
            )
         ON CONFLICT (tenant_id, source, url) DO UPDATE SET
            classification = EXCLUDED.classification,
            http_status = EXCLUDED.http_status,
            markers = EXCLUDED.markers,
            detail = EXCLUDED.detail,
            retry_after = EXCLUDED.retry_after,
            occurrences = sales_scrape_blocked_sources.occurrences + 1,
            last_seen_at = NOW(),
            last_job_id = COALESCE(EXCLUDED.last_job_id, sales_scrape_blocked_sources.last_job_id),
            state = 'open'
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(source)
    .bind(&blocked.url)
    .bind(&blocked.host)
    .bind(blocked.classification.as_str())
    .bind(blocked.http_status.map(i32::from))
    .bind(&blocked.markers)
    .bind(&blocked.detail)
    .bind(retry_after)
    .bind(job_id)
    .bind(job_id)
    .bind(lease_token)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    Ok(id)
}

/// Persist a host's block state (called with the registry's post-block
/// snapshot, so the database and the in-process enforcement agree).
pub async fn record_host_block(
    db: &PgPool,
    tenant_id: &str,
    classification: FetchClassification,
    host_state: &super::fetch::HostState,
) -> Result<(), SalesError> {
    if host_state.host.is_empty() {
        return Err(SalesError::InvalidInput(
            "host health write without a host".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO sales_scrape_host_health (
            tenant_id, host, consecutive_blocks, total_blocks, last_classification,
            last_status, last_blocked_at, blocked_until, updated_at
         )
         VALUES ($1, $2, $3, 1, $4, $5, NOW(), $6, NOW())
         ON CONFLICT (tenant_id, host) DO UPDATE SET
            consecutive_blocks = EXCLUDED.consecutive_blocks,
            total_blocks = sales_scrape_host_health.total_blocks + 1,
            last_classification = EXCLUDED.last_classification,
            last_status = EXCLUDED.last_status,
            last_blocked_at = NOW(),
            blocked_until = EXCLUDED.blocked_until,
            updated_at = NOW()",
    )
    .bind(tenant_id)
    .bind(&host_state.host)
    .bind(host_state.consecutive_blocks as i32)
    .bind(classification.as_str())
    .bind(host_state.last_status.map(i32::from))
    .bind(host_state.blocked_until)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// Clear a host's block state after a successful fetch.
pub async fn record_host_success(
    db: &PgPool,
    tenant_id: &str,
    host: &str,
) -> Result<(), SalesError> {
    sqlx::query(
        "INSERT INTO sales_scrape_host_health (
            tenant_id, host, consecutive_blocks, total_blocks, last_classification,
            last_success_at, blocked_until, updated_at
         )
         VALUES ($1, $2, 0, 0, 'ok', NOW(), NULL, NOW())
         ON CONFLICT (tenant_id, host) DO UPDATE SET
            consecutive_blocks = 0,
            last_classification = 'ok',
            last_success_at = NOW(),
            blocked_until = NULL,
            updated_at = NOW()",
    )
    .bind(tenant_id)
    .bind(host)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// The blocked-source queue, newest evidence first.
///
/// `state` filters on the review state (`open`, `solved`, `dismissed`);
/// `None` lists everything.
pub async fn list_blocked_sources(
    db: &PgPool,
    tenant_id: &str,
    state: Option<&str>,
    limit: i64,
) -> Result<Vec<BlockedSource>, SalesError> {
    let limit = limit.clamp(1, 500);
    let rows: Vec<BlockedSource> = sqlx::query_as(
        "SELECT id, tenant_id, source, url, host, classification, http_status, markers,
                detail, retry_after, occurrences, state, first_seen_at, last_seen_at,
                last_job_id, reviewed_by, reviewed_at, review_note
         FROM sales_scrape_blocked_sources
         WHERE tenant_id = $1 AND ($2::text IS NULL OR state = $2)
         ORDER BY last_seen_at DESC, url ASC
         LIMIT $3",
    )
    .bind(tenant_id)
    .bind(state)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(rows)
}

/// Load one queue row, tenant-scoped.
pub async fn get_blocked_source(
    db: &PgPool,
    tenant_id: &str,
    id: Uuid,
) -> Result<BlockedSource, SalesError> {
    let row: Option<BlockedSource> = sqlx::query_as(
        "SELECT id, tenant_id, source, url, host, classification, http_status, markers,
                detail, retry_after, occurrences, state, first_seen_at, last_seen_at,
                last_job_id, reviewed_by, reviewed_at, review_note
         FROM sales_scrape_blocked_sources
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    row.ok_or_else(|| {
        SalesError::InvalidInput(format!(
            "blocked source {id} not found for tenant {tenant_id}"
        ))
    })
}

/// What an operator can do with a queue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReviewAction {
    /// Closed: the challenge was solved (by the hook or by hand).
    Solved,
    /// Closed: reviewed and deliberately not pursued.
    Dismissed,
    /// Re-open a closed row for another look.
    Reopen,
}

impl BlockedReviewAction {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "solved" => Some(Self::Solved),
            "dismissed" => Some(Self::Dismissed),
            "reopen" => Some(Self::Reopen),
            _ => None,
        }
    }

    fn target_state(self) -> &'static str {
        match self {
            Self::Solved => BLOCKED_STATE_SOLVED,
            Self::Dismissed => BLOCKED_STATE_DISMISSED,
            Self::Reopen => BLOCKED_STATE_OPEN,
        }
    }
}

/// Apply an operator review decision. The reviewer is required (an
/// unattributed decision on a scraping block is not auditable), and the
/// transition must make sense: closing requires an open row, reopening
/// requires a closed one.
pub async fn review_blocked_source(
    db: &PgPool,
    tenant_id: &str,
    id: Uuid,
    action: BlockedReviewAction,
    reviewer: &str,
    note: Option<&str>,
) -> Result<BlockedSource, SalesError> {
    let reviewer = reviewer.trim();
    if reviewer.is_empty() {
        return Err(SalesError::InvalidInput(
            "a blocked-source review requires a reviewer identity".into(),
        ));
    }
    let note = note.map(str::trim).filter(|value| !value.is_empty());
    if action == BlockedReviewAction::Dismissed && note.is_none() {
        return Err(SalesError::InvalidInput(
            "dismissing a blocked source requires a note saying why".into(),
        ));
    }

    let current = get_blocked_source(db, tenant_id, id).await?;
    let transition_ok = match action {
        BlockedReviewAction::Reopen => current.state != BLOCKED_STATE_OPEN,
        _ => current.state == BLOCKED_STATE_OPEN,
    };
    if !transition_ok {
        return Err(SalesError::InvalidInput(format!(
            "blocked source {id} is {} — `{}` is not a valid transition from that state",
            current.state,
            action.target_state()
        )));
    }

    let updated: Option<BlockedSource> = sqlx::query_as(
        "UPDATE sales_scrape_blocked_sources
         SET state = $3, reviewed_by = $4, reviewed_at = NOW(), review_note = $5
         WHERE id = $1 AND tenant_id = $2
         RETURNING id, tenant_id, source, url, host, classification, http_status, markers,
                   detail, retry_after, occurrences, state, first_seen_at, last_seen_at,
                   last_job_id, reviewed_by, reviewed_at, review_note",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(action.target_state())
    .bind(reviewer)
    .bind(note)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    updated.ok_or_else(|| {
        SalesError::InvalidInput(format!(
            "blocked source {id} not found for tenant {tenant_id}"
        ))
    })
}

/// Host health rows for the admin surface, worst first.
pub async fn list_host_health(
    db: &PgPool,
    tenant_id: &str,
    limit: i64,
) -> Result<Vec<HostHealthRow>, SalesError> {
    let rows: Vec<HostHealthRow> = sqlx::query_as(
        "SELECT host, consecutive_blocks, total_blocks, last_classification, last_status,
                last_blocked_at, last_success_at, blocked_until, solver_enabled,
                solver_enabled_at, solver_enabled_by, updated_at
         FROM sales_scrape_host_health
         WHERE tenant_id = $1
         ORDER BY (blocked_until IS NOT NULL AND blocked_until > NOW()) DESC,
                  total_blocks DESC, host ASC
         LIMIT $2",
    )
    .bind(tenant_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(rows)
}

/// One host's health row.
pub async fn get_host_health(
    db: &PgPool,
    tenant_id: &str,
    host: &str,
) -> Result<Option<HostHealthRow>, SalesError> {
    let row: Option<HostHealthRow> = sqlx::query_as(
        "SELECT host, consecutive_blocks, total_blocks, last_classification, last_status,
                last_blocked_at, last_success_at, blocked_until, solver_enabled,
                solver_enabled_at, solver_enabled_by, updated_at
         FROM sales_scrape_host_health
         WHERE tenant_id = $1 AND host = $2",
    )
    .bind(tenant_id)
    .bind(host)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(row)
}

/// Record (or revoke) an operator's solver opt-in for one host.
///
/// This is the ONLY way `solver_enabled` becomes true; it is deliberately
/// separate from any fetch path, so no scrape can opt itself in.
pub async fn set_host_solver_optin(
    db: &PgPool,
    tenant_id: &str,
    host: &str,
    enabled: bool,
    operator: &str,
) -> Result<HostHealthRow, SalesError> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(SalesError::InvalidInput("invalid host".into()));
    }
    let operator = operator.trim();
    if operator.is_empty() {
        return Err(SalesError::InvalidInput(
            "the solver opt-in requires an operator identity".into(),
        ));
    }
    let row: HostHealthRow = sqlx::query_as(
        "INSERT INTO sales_scrape_host_health (
            tenant_id, host, solver_enabled, solver_enabled_at, solver_enabled_by, updated_at
         )
         VALUES ($1, $2, $3, CASE WHEN $3 THEN NOW() ELSE NULL END,
                 CASE WHEN $3 THEN $4 ELSE NULL END, NOW())
         ON CONFLICT (tenant_id, host) DO UPDATE SET
            solver_enabled = EXCLUDED.solver_enabled,
            solver_enabled_at = EXCLUDED.solver_enabled_at,
            solver_enabled_by = EXCLUDED.solver_enabled_by,
            updated_at = NOW()
         RETURNING host, consecutive_blocks, total_blocks, last_classification, last_status,
                   last_blocked_at, last_success_at, blocked_until, solver_enabled,
                   solver_enabled_at, solver_enabled_by, updated_at",
    )
    .bind(tenant_id)
    .bind(&host)
    .bind(enabled)
    .bind(operator)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(row)
}

/// Load a tenant's persisted host state into the in-process registry, so a
/// fresh process cannot hand an attacking host a clean slate.
pub async fn hydrate_registry(
    db: &PgPool,
    tenant_id: &str,
    registry: &super::fetch::HostHealthRegistry,
) -> Result<usize, SalesError> {
    let rows: Vec<HostHealthRow> = sqlx::query_as(
        "SELECT host, consecutive_blocks, total_blocks, last_classification, last_status,
                last_blocked_at, last_success_at, blocked_until, solver_enabled,
                solver_enabled_at, solver_enabled_by, updated_at
         FROM sales_scrape_host_health
         WHERE tenant_id = $1 AND (blocked_until IS NOT NULL OR solver_enabled)
         ORDER BY updated_at DESC
         LIMIT 500",
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let count = rows.len();
    for row in rows {
        registry.hydrate(super::fetch::HostState {
            host: row.host,
            consecutive_blocks: row.consecutive_blocks.max(0) as u32,
            total_blocks: row.total_blocks.max(0) as u64,
            last_classification: row
                .last_classification
                .as_deref()
                .and_then(FetchClassification::parse),
            last_status: row.last_status.map(|status| status as u16),
            last_blocked_at: row.last_blocked_at,
            last_success_at: row.last_success_at,
            blocked_until: row.blocked_until,
            solver_enabled: row.solver_enabled,
        });
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// The audited solver hook
// ---------------------------------------------------------------------------

/// Solver hook configuration. Disabled unless the URL is configured.
#[derive(Debug, Clone, PartialEq)]
pub struct SolverConfig {
    pub url: Option<String>,
    pub token: Option<String>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            url: None,
            token: None,
            timeout: Duration::from_secs(30),
            max_response_bytes: 64 * 1024,
        }
    }
}

/// Environment variable naming the operator's solver service.
pub const SOLVER_URL_ENV: &str = "SCRAPE_CAPTCHA_SOLVER_URL";
/// Environment variable holding the solver bearer token.
pub const SOLVER_TOKEN_ENV: &str = "SCRAPE_CAPTCHA_SOLVER_TOKEN";
/// Environment variable overriding the solver timeout.
pub const SOLVER_TIMEOUT_ENV: &str = "SCRAPE_CAPTCHA_SOLVER_TIMEOUT_MS";

impl SolverConfig {
    /// Read the hook configuration. An unset or non-http(s) URL leaves the
    /// hook DISABLED (a misconfigured solver must not become a default one).
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(raw) = std::env::var(SOLVER_URL_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            match url::Url::parse(&raw) {
                Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => {
                    config.url = Some(raw);
                }
                _ => tracing::warn!(
                    variable = SOLVER_URL_ENV,
                    "solver URL is not a valid http(s) URL; the hook stays disabled"
                ),
            }
        }
        config.token = std::env::var(SOLVER_TOKEN_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if let Ok(raw) = std::env::var(SOLVER_TIMEOUT_ENV) {
            match raw.trim().parse::<u64>() {
                Ok(ms) if ms > 0 => config.timeout = Duration::from_millis(ms.min(300_000)),
                _ => tracing::warn!(
                    variable = SOLVER_TIMEOUT_ENV,
                    "invalid solver timeout; keeping the default"
                ),
            }
        }
        config
    }

    pub fn is_configured(&self) -> bool {
        self.url.is_some()
    }
}

/// The documented outcome vocabulary of a solve attempt (persisted in
/// `sales_scrape_solver_audit.outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverOutcome {
    /// Gate 1 closed: no URL configured, so nothing was called.
    Disabled,
    /// Gate 2 closed: the host is not opted in.
    HostNotOptedIn,
    /// Gate 3 closed: the host is inside its backoff window.
    BackoffActive,
    /// The queue row is not a CAPTCHA block (policy/transient blocks have
    /// nothing to solve), or it is already closed.
    Ineligible,
    /// The solver was called and failed (timeout, non-2xx, unparseable).
    SolverFailed,
    /// The solver returned material and the single retry fetched the page.
    RetryOk,
    /// The solver returned material and the retry was blocked again.
    RetryBlocked,
}

impl SolverOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::HostNotOptedIn => "host_not_opted_in",
            Self::BackoffActive => "backoff_active",
            Self::Ineligible => "ineligible",
            Self::SolverFailed => "solver_failed",
            Self::RetryOk => "retry_ok",
            Self::RetryBlocked => "retry_blocked",
        }
    }

    /// Parse a persisted outcome; unknown values are `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "disabled" => Some(Self::Disabled),
            "host_not_opted_in" => Some(Self::HostNotOptedIn),
            "backoff_active" => Some(Self::BackoffActive),
            "ineligible" => Some(Self::Ineligible),
            "solver_failed" => Some(Self::SolverFailed),
            "retry_ok" => Some(Self::RetryOk),
            "retry_blocked" => Some(Self::RetryBlocked),
            _ => None,
        }
    }
}

/// The report of one solve attempt. `audited` is always true: every attempt
/// writes an audit row, including the refused ones.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolveReport {
    pub outcome: SolverOutcome,
    pub audit_id: Uuid,
    pub host: String,
    pub url: String,
    pub retried: bool,
    pub retry_classification: Option<String>,
    pub detail: Option<String>,
}

/// The solver's response contract. `solved` MUST carry retry material
/// (`cookie` and/or `headers`); `failed` MAY carry a detail.
#[derive(Debug, Clone, Deserialize)]
struct SolverResponse {
    status: String,
    #[serde(default)]
    cookie: Option<String>,
    #[serde(default)]
    headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    detail: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    db: &PgPool,
    tenant_id: &str,
    blocked_source_id: Uuid,
    host: &str,
    url: &str,
    outcome: SolverOutcome,
    detail: Option<&str>,
    solver_latency_ms: Option<i64>,
    token_received: bool,
    retried: bool,
    retry_classification: Option<&str>,
    retry_http_status: Option<u16>,
) -> Result<Uuid, SalesError> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_scrape_solver_audit (
            id, tenant_id, blocked_source_id, host, url, outcome, detail,
            solver_latency_ms, token_received, retried, retry_classification,
            retry_http_status, attempted_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(blocked_source_id)
    .bind(host)
    .bind(url)
    .bind(outcome.as_str())
    .bind(detail)
    .bind(solver_latency_ms)
    .bind(token_received)
    .bind(retried)
    .bind(retry_classification)
    .bind(retry_http_status.map(i32::from))
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(id)
}

/// Attempt the operator-gated solve of one blocked CAPTCHA source.
///
/// The three gates are checked in order, and every outcome — including every
/// refusal — is audited. See the module docs for the contract.
pub async fn attempt_solve(
    db: &PgPool,
    client: &ScrapeClient,
    tenant_id: &str,
    blocked_source_id: Uuid,
    solver: &SolverConfig,
    operator: Option<&str>,
) -> Result<SolveReport, SalesError> {
    let blocked = get_blocked_source(db, tenant_id, blocked_source_id).await?;
    let note = |detail: String| Some(detail);

    // Gate 1: the hook is configured. Nothing is called when it is not.
    if !solver.is_configured() {
        let detail =
            format!("{SOLVER_URL_ENV} is not configured; the solver hook is disabled by default");
        let audit_id = audit(
            db,
            tenant_id,
            blocked.id,
            &blocked.host,
            &blocked.url,
            SolverOutcome::Disabled,
            Some(&detail),
            None,
            false,
            false,
            None,
            None,
        )
        .await?;
        return Ok(SolveReport {
            outcome: SolverOutcome::Disabled,
            audit_id,
            host: blocked.host.clone(),
            url: blocked.url.clone(),
            retried: false,
            retry_classification: None,
            detail: Some(detail),
        });
    }

    // Gate 2: an operator opted this host in (stored, per host).
    let health = get_host_health(db, tenant_id, &blocked.host).await?;
    let opted_in = health
        .as_ref()
        .map(|row| row.solver_enabled)
        .unwrap_or(false);
    if !opted_in {
        let detail = format!(
            "host {} is not opted in to the solver (solver_enabled = false); an operator must \
             enable it explicitly",
            blocked.host
        );
        let audit_id = audit(
            db,
            tenant_id,
            blocked.id,
            &blocked.host,
            &blocked.url,
            SolverOutcome::HostNotOptedIn,
            Some(&detail),
            None,
            false,
            false,
            None,
            None,
        )
        .await?;
        return Ok(SolveReport {
            outcome: SolverOutcome::HostNotOptedIn,
            audit_id,
            host: blocked.host.clone(),
            url: blocked.url.clone(),
            retried: false,
            retry_classification: None,
            detail: Some(detail),
        });
    }

    // Only a CAPTCHA block is solvable, and only while it is open.
    let classification = FetchClassification::parse(&blocked.classification);
    if classification != Some(FetchClassification::BlockedCaptcha)
        || blocked.state != BLOCKED_STATE_OPEN
    {
        let detail = format!(
            "blocked source is {} ({}) — only an open blocked_captcha row can be solved",
            blocked.state, blocked.classification
        );
        let audit_id = audit(
            db,
            tenant_id,
            blocked.id,
            &blocked.host,
            &blocked.url,
            SolverOutcome::Ineligible,
            Some(&detail),
            None,
            false,
            false,
            None,
            None,
        )
        .await?;
        return Ok(SolveReport {
            outcome: SolverOutcome::Ineligible,
            audit_id,
            host: blocked.host.clone(),
            url: blocked.url.clone(),
            retried: false,
            retry_classification: None,
            detail: Some(detail),
        });
    }

    // Gate 3: no active backoff window. A solve must never be a way around
    // the host's penalty, so this is checked against BOTH the persisted row
    // and the in-process registry.
    let persisted_backoff = health.as_ref().and_then(|row| row.blocked_until);
    let backoff_active = persisted_backoff
        .map(|until| until > Utc::now())
        .unwrap_or(false)
        || client
            .host_health()
            .backoff_until(&blocked.host)
            .map(|until| until > tokio::time::Instant::now())
            .unwrap_or(false);
    if backoff_active {
        let until = persisted_backoff.map(|until| until.to_rfc3339());
        let detail = format!(
            "host {} is inside its backoff window{}; nothing bypasses the per-host backoff",
            blocked.host,
            until
                .map(|until| format!(" (until {until})"))
                .unwrap_or_default()
        );
        let audit_id = audit(
            db,
            tenant_id,
            blocked.id,
            &blocked.host,
            &blocked.url,
            SolverOutcome::BackoffActive,
            Some(&detail),
            None,
            false,
            false,
            None,
            None,
        )
        .await?;
        return Ok(SolveReport {
            outcome: SolverOutcome::BackoffActive,
            audit_id,
            host: blocked.host.clone(),
            url: blocked.url.clone(),
            retried: false,
            retry_classification: None,
            detail: Some(detail),
        });
    }

    // Call the operator's solver. The request carries the challenge metadata
    // and the blocked URL; the token (when configured) is sent as a bearer
    // header and never redirected (redirects are refused outright).
    let request_body = serde_json::json!({
        "url": blocked.url,
        "host": blocked.host,
        "source": blocked.source,
        "classification": blocked.classification,
        "http_status": blocked.http_status,
        "markers": blocked.markers,
        "detail": blocked.detail,
        "first_seen_at": blocked.first_seen_at,
        "user_agent": client.config().user_agent,
        "operator": operator,
    });
    let started = std::time::Instant::now();
    let solver_call = call_solver(solver, &request_body).await;
    let latency_ms = started.elapsed().as_millis() as i64;

    let solved = match solver_call {
        Ok(response) if response.status.eq_ignore_ascii_case("solved") => response,
        Ok(response) => {
            let detail = response
                .detail
                .unwrap_or_else(|| format!("solver reported status {}", response.status));
            let audit_id = audit(
                db,
                tenant_id,
                blocked.id,
                &blocked.host,
                &blocked.url,
                SolverOutcome::SolverFailed,
                note(detail.clone()).as_deref(),
                Some(latency_ms),
                false,
                false,
                None,
                None,
            )
            .await?;
            let state = client.host_health().note_blocked(
                &blocked.host,
                FetchClassification::BlockedTransient,
                blocked.http_status.map(|status| status as u16),
            );
            record_host_block(db, tenant_id, FetchClassification::BlockedTransient, &state).await?;
            return Ok(SolveReport {
                outcome: SolverOutcome::SolverFailed,
                audit_id,
                host: blocked.host.clone(),
                url: blocked.url.clone(),
                retried: false,
                retry_classification: None,
                detail: Some(detail),
            });
        }
        Err(detail) => {
            let audit_id = audit(
                db,
                tenant_id,
                blocked.id,
                &blocked.host,
                &blocked.url,
                SolverOutcome::SolverFailed,
                Some(&detail),
                Some(latency_ms),
                false,
                false,
                None,
                None,
            )
            .await?;
            // Hook failure backs off: a broken or slow solver must not turn
            // into an unbounded retry loop against the target.
            let state = client.host_health().note_blocked(
                &blocked.host,
                FetchClassification::BlockedTransient,
                blocked.http_status.map(|status| status as u16),
            );
            record_host_block(db, tenant_id, FetchClassification::BlockedTransient, &state).await?;
            return Ok(SolveReport {
                outcome: SolverOutcome::SolverFailed,
                audit_id,
                host: blocked.host.clone(),
                url: blocked.url.clone(),
                retried: false,
                retry_classification: None,
                detail: Some(detail),
            });
        }
    };

    // The solve material must be retry-safe: validated for CR/LF injection
    // and length in the fetch layer, applied to ONE retry, same host only.
    let cookie = solved.cookie.as_deref();
    let header_pairs: Vec<(String, String)> =
        solved.headers.unwrap_or_default().into_iter().collect();
    let token_received = cookie.is_some() || !header_pairs.is_empty();
    let retry = client
        .fetch_once_with_solve_material(&blocked.url, cookie, &header_pairs)
        .await;

    match retry {
        Ok(page) => {
            sqlx::query(
                "UPDATE sales_scrape_blocked_sources
                 SET state = 'solved', reviewed_by = $3, reviewed_at = NOW(),
                     review_note = $4
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(blocked.id)
            .bind(tenant_id)
            .bind(operator.unwrap_or("captcha-solver"))
            .bind("solved by the configured solver hook; the retry fetched the page")
            .execute(db)
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
            let detail = format!(
                "solver returned material; the single retry fetched {} bytes of {}",
                page.body_bytes, page.content_type
            );
            let audit_id = audit(
                db,
                tenant_id,
                blocked.id,
                &blocked.host,
                &blocked.url,
                SolverOutcome::RetryOk,
                Some(&detail),
                Some(latency_ms),
                token_received,
                true,
                Some(FetchClassification::Ok.as_str()),
                Some(page.status),
            )
            .await?;
            Ok(SolveReport {
                outcome: SolverOutcome::RetryOk,
                audit_id,
                host: blocked.host.clone(),
                url: blocked.url.clone(),
                retried: true,
                retry_classification: Some(FetchClassification::Ok.as_str().to_string()),
                detail: Some(detail),
            })
        }
        Err(error) => {
            let retry_classification = error.classification();
            // A blocked retry is fresh evidence for the queue (and the fetch
            // layer already updated the host backoff window).
            if let Some(evidence) = BlockedEvidence::from_fetch_error(&error) {
                record_blocked_fetch(db, tenant_id, &blocked.source, None, &evidence).await?;
            }
            let detail = format!(
                "solver returned material but the single retry failed: {}",
                error
            );
            let retry_http_status = match &error {
                super::fetch::FetchError::Blocked(evidence) => evidence.http_status,
                super::fetch::FetchError::HttpStatus { status, .. } => Some(*status),
                _ => None,
            };
            let audit_id = audit(
                db,
                tenant_id,
                blocked.id,
                &blocked.host,
                &blocked.url,
                SolverOutcome::RetryBlocked,
                Some(&detail),
                Some(latency_ms),
                token_received,
                true,
                retry_classification.map(FetchClassification::as_str),
                retry_http_status,
            )
            .await?;
            Ok(SolveReport {
                outcome: SolverOutcome::RetryBlocked,
                audit_id,
                host: blocked.host.clone(),
                url: blocked.url.clone(),
                retried: true,
                retry_classification: retry_classification
                    .map(|classification| classification.as_str().to_string()),
                detail: Some(detail),
            })
        }
    }
}

/// POST the challenge metadata to the configured solver. Redirects are never
/// followed (the bearer token must not travel), the response is size-capped,
/// and only a 2xx JSON body is accepted.
async fn call_solver(
    solver: &SolverConfig,
    body: &serde_json::Value,
) -> Result<SolverResponse, String> {
    let url = solver
        .url
        .as_deref()
        .ok_or_else(|| "solver URL is not configured".to_string())?;
    let client = reqwest::Client::builder()
        .timeout(solver.timeout)
        .connect_timeout(Duration::from_secs(5))
        .user_agent("ApexMail/1.0 (captcha-solver-hook)")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("failed to build the solver HTTP client: {error}"))?;
    let mut request = client.post(url).json(body);
    if let Some(token) = &solver.token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("solver request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("solver returned HTTP {status}"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("solver response read failed: {error}"))?;
    if bytes.len() > solver.max_response_bytes {
        return Err(format!(
            "solver response exceeds {} bytes",
            solver.max_response_bytes
        ));
    }
    serde_json::from_slice::<SolverResponse>(&bytes)
        .map_err(|error| format!("solver response is not the documented JSON: {error}"))
}

// ---------------------------------------------------------------------------
// Tests — pure (no database, no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solver_config_is_disabled_by_default() {
        // The default IS the disabled hook: no URL means no call.
        let config = SolverConfig::default();
        assert!(!config.is_configured());
        assert_eq!(config.url, None);
        assert!(config.timeout <= Duration::from_secs(120));
        assert!(config.max_response_bytes <= 1024 * 1024);
    }

    #[test]
    fn solver_config_from_env_validates_the_url_and_restores_the_environment() {
        let previous_url = std::env::var(SOLVER_URL_ENV).ok();
        let previous_timeout = std::env::var(SOLVER_TIMEOUT_ENV).ok();

        // A non-http(s) value leaves the hook DISABLED rather than pointing
        // it somewhere unexpected.
        std::env::set_var(SOLVER_URL_ENV, "ftp://solver.example/solve");
        assert!(!SolverConfig::from_env().is_configured());

        std::env::set_var(SOLVER_URL_ENV, "https://solver.example/solve");
        std::env::set_var(SOLVER_TIMEOUT_ENV, "not-a-number");
        let config = SolverConfig::from_env();
        assert!(config.is_configured());
        assert_eq!(config.url.as_deref(), Some("https://solver.example/solve"));
        assert_eq!(
            config.timeout,
            SolverConfig::default().timeout,
            "an invalid timeout keeps the default"
        );

        std::env::set_var(SOLVER_TIMEOUT_ENV, "5000");
        assert_eq!(
            SolverConfig::from_env().timeout,
            Duration::from_millis(5_000)
        );

        match previous_url {
            Some(value) => std::env::set_var(SOLVER_URL_ENV, value),
            None => std::env::remove_var(SOLVER_URL_ENV),
        }
        match previous_timeout {
            Some(value) => std::env::set_var(SOLVER_TIMEOUT_ENV, value),
            None => std::env::remove_var(SOLVER_TIMEOUT_ENV),
        }
    }

    #[test]
    fn solver_outcomes_round_trip() {
        for outcome in [
            SolverOutcome::Disabled,
            SolverOutcome::HostNotOptedIn,
            SolverOutcome::BackoffActive,
            SolverOutcome::Ineligible,
            SolverOutcome::SolverFailed,
            SolverOutcome::RetryOk,
            SolverOutcome::RetryBlocked,
        ] {
            assert_eq!(SolverOutcome::parse(outcome.as_str()), Some(outcome));
        }
        assert_eq!(SolverOutcome::parse("solved"), None);
        assert_eq!(SolverOutcome::parse(""), None);
    }

    #[test]
    fn review_actions_parse_only_the_documented_words() {
        assert_eq!(
            BlockedReviewAction::parse("solved"),
            Some(BlockedReviewAction::Solved)
        );
        assert_eq!(
            BlockedReviewAction::parse("DISMISSED"),
            Some(BlockedReviewAction::Dismissed)
        );
        assert_eq!(
            BlockedReviewAction::parse(" reopen "),
            Some(BlockedReviewAction::Reopen)
        );
        assert_eq!(BlockedReviewAction::parse("delete"), None);
        assert_eq!(
            BlockedReviewAction::Solved.target_state(),
            BLOCKED_STATE_SOLVED
        );
        assert_eq!(
            BlockedReviewAction::Dismissed.target_state(),
            BLOCKED_STATE_DISMISSED
        );
        assert_eq!(
            BlockedReviewAction::Reopen.target_state(),
            BLOCKED_STATE_OPEN
        );
    }

    #[test]
    fn solver_response_contract_parses_solved_and_failed_shapes() {
        let solved: SolverResponse = serde_json::from_str(
            r#"{"status":"solved","cookie":"cf_clearance=x","headers":{"X-Token":"y"}}"#,
        )
        .expect("solved shape");
        assert_eq!(solved.status, "solved");
        assert_eq!(solved.cookie.as_deref(), Some("cf_clearance=x"));
        assert_eq!(
            solved
                .headers
                .as_ref()
                .and_then(|headers| headers.get("X-Token"))
                .map(String::as_str),
            Some("y")
        );

        let failed: SolverResponse =
            serde_json::from_str(r#"{"status":"failed","detail":"human required"}"#)
                .expect("failed shape");
        assert_eq!(failed.detail.as_deref(), Some("human required"));
        assert!(failed.cookie.is_none());

        // An undocumented shape is a parse error, never a silent success.
        assert!(serde_json::from_str::<SolverResponse>(r#"{"result":"ok"}"#).is_err());
    }
}
