//! Blocked-source queue, persistent host health, and permanent host exclusion.
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
//!                                                                     exclusion)
//!                                    sales_scrape_host_exclusion_audit
//! ```
//!
//! # The permanent host exclusion
//!
//! There is no CAPTCHA solving, outsourcing or evasion; no proxy rotation and
//! no residential exit pools after a block; no stealth browser; no page
//! behind a login. The owner's decision is encoded as a one-way state machine:
//!
//! | trigger | `exclusion_reason` |
//! |---|---|
//! | a CAPTCHA/challenge page (`blocked_captcha`) | `captcha` |
//! | a `robots.txt` disallow (`blocked_policy`, no HTTP status) | `robots_disallow` |
//! | HTTP 401 | `http_401` |
//! | HTTP 403 | `http_403` |
//! | three 429 responses in a row | `http_429_repeated` |
//!
//! The state is persisted in `sales_scrape_host_health.excluded_at` /
//! `exclusion_reason` and hydrated into the in-process registry, so a fresh
//! process cannot hand an excluded host a clean slate. `ScrapeClient::fetch`
//! checks it BEFORE anything else: an excluded host receives no request at
//! all, not even `robots.txt`.
//!
//! The transition into exclusion is one-way for the engine: no fetch, retry,
//! review decision or setting clears it. Only [`lift_host_exclusion`] does,
//! and it is owner-only by construction (the whole service is the platform
//! owner's system-tenant surface, authenticated by the internal token). A
//! lift requires a non-empty owner identity AND a written reason; both are
//! stored in `sales_scrape_host_exclusion_audit` alongside the automatic
//! exclusion events.
//!
//! # What this module deliberately does NOT do
//!
//! No challenge-solving client, settings, attempt or audit, and no retry with
//! acquired cookies or headers. A block ends the conversation with that host.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::fetch::{BlockedEvidence, FetchClassification};
use crate::types::SalesError;

/// Queue states. Owned here (the migration is deliberately CHECK-free so a
/// future state does not need a schema change).
pub const BLOCKED_STATE_OPEN: &str = "open";
pub const BLOCKED_STATE_SOLVED: &str = "solved";
pub const BLOCKED_STATE_DISMISSED: &str = "dismissed";

/// Audit actions recorded in `sales_scrape_host_exclusion_audit`.
pub const EXCLUSION_AUDIT_EXCLUDED: &str = "excluded";
pub const EXCLUSION_AUDIT_LIFTED: &str = "lifted";

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
    pub consecutive_429: i32,
    pub last_classification: Option<String>,
    pub last_status: Option<i32>,
    pub last_blocked_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub blocked_until: Option<DateTime<Utc>>,
    pub excluded_at: Option<DateTime<Utc>>,
    pub exclusion_reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// One row of `sales_scrape_host_exclusion_audit`: the written record of
/// every automatic exclusion and every owner lift.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct HostExclusionAuditRow {
    pub id: Uuid,
    pub tenant_id: String,
    pub host: String,
    pub action: String,
    pub reason: String,
    pub detail: Option<String>,
    pub actor: String,
    pub created_at: DateTime<Utc>,
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
/// supplied and no longer owns the job (the write was refused, the caller
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
///
/// When the snapshot carries a permanent exclusion and the stored row did
/// not already have one, the automatic exclusion is written to
/// `sales_scrape_host_exclusion_audit` in the same transaction. The first
/// exclusion reason is kept: later failures cannot rewrite the cause.
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
    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let prior: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
        "SELECT excluded_at FROM sales_scrape_host_health \
         WHERE tenant_id = $1 AND host = $2",
    )
    .bind(tenant_id)
    .bind(&host_state.host)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let was_excluded = prior.flatten().is_some();

    sqlx::query(
        "INSERT INTO sales_scrape_host_health (
            tenant_id, host, consecutive_blocks, total_blocks, consecutive_429,
            last_classification, last_status, last_blocked_at, blocked_until,
            excluded_at, exclusion_reason, updated_at
         )
         VALUES ($1, $2, $3, 1, $4, $5, $6, NOW(), $7, $8, $9, NOW())
         ON CONFLICT (tenant_id, host) DO UPDATE SET
            consecutive_blocks = EXCLUDED.consecutive_blocks,
            total_blocks = sales_scrape_host_health.total_blocks + 1,
            consecutive_429 = EXCLUDED.consecutive_429,
            last_classification = EXCLUDED.last_classification,
            last_status = EXCLUDED.last_status,
            last_blocked_at = NOW(),
            blocked_until = EXCLUDED.blocked_until,
            excluded_at = COALESCE(
                sales_scrape_host_health.excluded_at,
                EXCLUDED.excluded_at
            ),
            exclusion_reason = COALESCE(
                sales_scrape_host_health.exclusion_reason,
                EXCLUDED.exclusion_reason
            ),
            updated_at = NOW()",
    )
    .bind(tenant_id)
    .bind(&host_state.host)
    .bind(host_state.consecutive_blocks as i32)
    .bind(host_state.consecutive_429 as i32)
    .bind(classification.as_str())
    .bind(host_state.last_status.map(i32::from))
    .bind(host_state.blocked_until)
    .bind(host_state.excluded_at)
    .bind(host_state.exclusion_reason.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    if !was_excluded {
        if let Some(reason) = host_state.exclusion_reason.as_deref() {
            let detail = format!(
                "automatic exclusion after a {} block{}",
                classification,
                host_state
                    .last_status
                    .map(|status| format!(" (HTTP {status})"))
                    .unwrap_or_default()
            );
            sqlx::query(
                "INSERT INTO sales_scrape_host_exclusion_audit (
                    id, tenant_id, host, action, reason, detail, actor, created_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, 'system', NOW())",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(&host_state.host)
            .bind(EXCLUSION_AUDIT_EXCLUDED)
            .bind(reason)
            .bind(detail)
            .execute(&mut *tx)
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        }
    }

    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// Clear a host's backoff and failure streaks after a successful fetch.
/// A permanent exclusion is deliberately NOT cleared here.
pub async fn record_host_success(
    db: &PgPool,
    tenant_id: &str,
    host: &str,
) -> Result<(), SalesError> {
    sqlx::query(
        "INSERT INTO sales_scrape_host_health (
            tenant_id, host, consecutive_blocks, total_blocks, consecutive_429,
            last_classification, last_success_at, blocked_until, updated_at
         )
         VALUES ($1, $2, 0, 0, 0, 'ok', NOW(), NULL, NOW())
         ON CONFLICT (tenant_id, host) DO UPDATE SET
            consecutive_blocks = 0,
            consecutive_429 = 0,
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
    /// Closed: reviewed and solved outside the engine (by hand).
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
///
/// A review decision resolves QUEUE rows only. It never lifts a host
/// exclusion: that requires [`lift_host_exclusion`] and an owner.
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
            "blocked source {id} is {}, `{}` is not a valid transition from that state",
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

const HOST_HEALTH_COLUMNS: &str = "host, consecutive_blocks, total_blocks, consecutive_429, \
     last_classification, last_status, last_blocked_at, last_success_at, blocked_until, \
     excluded_at, exclusion_reason, updated_at";

/// Host health rows for the admin surface, worst first.
pub async fn list_host_health(
    db: &PgPool,
    tenant_id: &str,
    limit: i64,
) -> Result<Vec<HostHealthRow>, SalesError> {
    let sql = format!(
        "SELECT {HOST_HEALTH_COLUMNS}
         FROM sales_scrape_host_health
         WHERE tenant_id = $1
         ORDER BY (exclusion_reason IS NOT NULL) DESC,
                  (blocked_until IS NOT NULL AND blocked_until > NOW()) DESC,
                  total_blocks DESC, host ASC
         LIMIT $2"
    );
    let rows: Vec<HostHealthRow> = sqlx::query_as(&sql)
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
    let sql = format!(
        "SELECT {HOST_HEALTH_COLUMNS}
         FROM sales_scrape_host_health
         WHERE tenant_id = $1 AND host = $2"
    );
    let row: Option<HostHealthRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(host)
        .fetch_optional(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(row)
}

/// Load a tenant's persisted host state into the in-process registry, so a
/// fresh process cannot hand an attacking or excluded host a clean slate.
pub async fn hydrate_registry(
    db: &PgPool,
    tenant_id: &str,
    registry: &super::fetch::HostHealthRegistry,
) -> Result<usize, SalesError> {
    let rows: Vec<HostHealthRow> = sqlx::query_as(
        "SELECT host, consecutive_blocks, total_blocks, consecutive_429,
                last_classification, last_status, last_blocked_at, last_success_at,
                blocked_until, excluded_at, exclusion_reason, updated_at
         FROM sales_scrape_host_health
         WHERE tenant_id = $1
           AND (blocked_until IS NOT NULL OR exclusion_reason IS NOT NULL)
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
            consecutive_429: row.consecutive_429.max(0) as u32,
            last_classification: row
                .last_classification
                .as_deref()
                .and_then(FetchClassification::parse),
            last_status: row.last_status.map(|status| status as u16),
            last_blocked_at: row.last_blocked_at,
            last_success_at: row.last_success_at,
            blocked_until: row.blocked_until,
            excluded_at: row.excluded_at,
            exclusion_reason: row.exclusion_reason,
        });
    }
    Ok(count)
}

/// Owner-only lift of one host's permanent exclusion.
///
/// The caller's surface is already the platform owner's system-tenant admin
/// API (internal token + system tenant). This function enforces the content
/// of the decision: a non-empty owner identity AND a non-empty written
/// reason are required, the host must actually be excluded, and the lift is
/// recorded in `sales_scrape_host_exclusion_audit` in the same transaction
/// that clears the state.
pub async fn lift_host_exclusion(
    db: &PgPool,
    tenant_id: &str,
    host: &str,
    owner: &str,
    reason: &str,
) -> Result<HostHealthRow, SalesError> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(SalesError::InvalidInput("invalid host".into()));
    }
    let owner = owner.trim();
    if owner.is_empty() {
        return Err(SalesError::InvalidInput(
            "lifting an exclusion requires the owner's identity".into(),
        ));
    }
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(SalesError::InvalidInput(
            "lifting an exclusion requires a written reason".into(),
        ));
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let prior: Option<(Option<DateTime<Utc>>, Option<String>)> = sqlx::query_as(
        "SELECT excluded_at, exclusion_reason FROM sales_scrape_host_health \
         WHERE tenant_id = $1 AND host = $2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&host)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let Some((excluded_at, previous_reason)) = prior else {
        return Err(SalesError::InvalidInput(format!(
            "host {host} has no health row for tenant {tenant_id}"
        )));
    };
    if excluded_at.is_none() && previous_reason.is_none() {
        return Err(SalesError::InvalidInput(format!(
            "host {host} is not excluded; there is nothing to lift"
        )));
    }

    let row: HostHealthRow = sqlx::query_as(
        "UPDATE sales_scrape_host_health
         SET excluded_at = NULL,
             exclusion_reason = NULL,
             consecutive_blocks = 0,
             consecutive_429 = 0,
             blocked_until = NULL,
             updated_at = NOW()
         WHERE tenant_id = $1 AND host = $2
         RETURNING host, consecutive_blocks, total_blocks, consecutive_429,
                   last_classification, last_status, last_blocked_at, last_success_at,
                   blocked_until, excluded_at, exclusion_reason, updated_at",
    )
    .bind(tenant_id)
    .bind(&host)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    sqlx::query(
        "INSERT INTO sales_scrape_host_exclusion_audit (
            id, tenant_id, host, action, reason, detail, actor, created_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(&host)
    .bind(EXCLUSION_AUDIT_LIFTED)
    .bind(reason)
    .bind(format!(
        "previous exclusion reason: {}",
        previous_reason.as_deref().unwrap_or("(not recorded)")
    ))
    .bind(owner)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(row)
}

/// The written exclusion audit, newest first (owner admin surface).
pub async fn list_host_exclusion_audit(
    db: &PgPool,
    tenant_id: &str,
    host: Option<&str>,
    limit: i64,
) -> Result<Vec<HostExclusionAuditRow>, SalesError> {
    let rows: Vec<HostExclusionAuditRow> = sqlx::query_as(
        "SELECT id, tenant_id, host, action, reason, detail, actor, created_at
         FROM sales_scrape_host_exclusion_audit
         WHERE tenant_id = $1 AND ($2::text IS NULL OR host = $2)
         ORDER BY created_at DESC, id DESC
         LIMIT $3",
    )
    .bind(tenant_id)
    .bind(host)
    .bind(limit.clamp(1, 500))
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Tests, pure (no database, no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
}
