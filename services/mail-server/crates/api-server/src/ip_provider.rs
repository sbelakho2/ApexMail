//! Dedicated IP provider — provisions IPs exclusively via Hetzner Cloud.
//!
//! In ApexMail's architecture, dedicated IPs are **always** Hetzner floating
//! IPs, routed through self-hosted MTA servers. There is no SES dedicated IP
//! path — SES is used exclusively for shared-pool sending.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐ ┌──────────────────────────┐
//! │ Shared send │──SES──▶ │ AWS SES shared IP pool │
//! └──────────────┘ └──────────────────────────┘
//!
//! ┌──────────────┐ ┌──────────────────────────┐
//! │ Dedicated IP │──SMTP─▶ │ Hetzner MTA servers │
//! │ send │ │ (floating IPs) │
//! └──────────────┘ └──────────────────────────┘
//! ```
//!
//! ## Seamless dual-path operation
//!
//! A tenant operates over SES shared IPs by default. When they upgrade to a
//! plan that includes dedicated IPs (or purchase add-on IPs), the billing
//! webhook calls `POST /v1/dedicated-ips` which runs
//! [`DedicatedIpProvider::allocate_ip`].
//!
//! ## Provisioning state machine
//!
//! Provisioning is an explicit state machine. [`DedicatedIpState`] and
//! [`transition`] are the single home for the lifecycle; every persisted
//! status write goes through the compare-and-swap methods of the
//! `ProvisioningStore` port, which refuse any transition the pure machine
//! rejects:
//!
//! ```text
//! provisioning → created → attached → rdns_ready → warming → active
//! ```
//!
//! * `provisioning` is the in-flight state before a `dedicated_ips` row can
//!   legally exist (`ip_address` is NOT NULL, and the address only exists
//!   after the provider creates the resource). It is therefore not persisted;
//!   the first persisted state is `created`.
//! * Only `warming` (with `warmup_started_at`) and `active` are selectable
//!   for sending. Every select path filters on exactly those statuses, so the
//!   intermediate states are unreachable by construction.
//! * `failed` is the terminal failure state; cleanup of the provider resource
//!   succeeded.
//! * `cleanup_failed` is the loud terminal state for "provider resource may
//!   still exist": `hetzner_floating_ip_id` and the provider response stay on
//!   the row and the row is the operator worklist. Query it with
//!   `SELECT id, tenant_id, hetzner_floating_ip_id, provisioning_error FROM
//!   dedicated_ips WHERE status = 'cleanup_failed'`.
//! * Existing failure/suspension vocabulary (`suspended`, `releasing`,
//!   `retired`, legacy `pending`/`cooldown`) is preserved; none of it is
//!   selectable.
//!
//! ## Failure and compensation rules
//!
//! * A failed attach or failed rDNS set/verification **deletes the floating
//!   IP** before the attempt is recorded.
//! * A DB write failure after the provider created the resource compensates
//!   by deleting the external resource. If that compensation fails, the row
//!   is recorded as `cleanup_failed`; if even that record cannot be written
//!   the identifiers are logged at ERROR level with the exact tenant,
//!   provider resource id and IP.
//! * rDNS is VERIFIED with an actual PTR lookup (`RdnsVerifier`), never
//!   inferred from the provider's 2xx.
//!
//! ## Concurrency and reconciliation
//!
//! Billing's auto-provision intentionally fires N concurrent allocate
//! requests for a tenant (one per purchased IP), so concurrent attempts are
//! legitimate and each owns a distinct floating IP. `run_provisioning`
//! serializes attempts inside the process and, when an attempt loses (DB
//! write refused after the provider resource exists), it deletes its own
//! resource — it never leaves an unrecorded, promotable IP. Stale in-flight
//! rows (`created`/`attached`/`rdns_ready` with an old `updated_at`) and
//! `cleanup_failed` rows are the documented reconciliation worklist; see
//! migration 207. For the crash window between the provider create and the
//! first DB write — where no row can exist yet — the floating IP is created
//! with the labels `service=apexmail` and `tenant_id=<tenant>`, so
//! `GET /floating_ips?label_selector=service=apexmail` on the provider lists
//! every resource that can then be matched against `dedicated_ips`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ─── Constants ─────────────────────────────────────────────────

/// Hetzner Cloud API base URL.
const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// Dedicated IP add-on price in cents/month.
pub const ADD_ON_PRICE_CENTS: i32 = 3000;

/// Statuses that do NOT occupy the tenant's dedicated-IP allowance.
///
/// `failed` never sends and its provider resource is gone; `cleanup_failed`
/// is a terminal incident record whose provider resource is tracked
/// separately. Both must not block a tenant from re-provisioning.
pub const NON_OCCUPYING_STATUSES: [&str; 4] = ["retired", "releasing", "failed", "cleanup_failed"];

/// The same list rendered for a SQL `NOT IN (...)` predicate. Keeps the
/// count queries in the API and billing service from drifting.
pub fn non_occupying_status_list_sql() -> String {
    NON_OCCUPYING_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Serializes provisioning attempts inside one process. The cross-replica
/// story is compensation (see module docs), not a lock: billing batches are
/// intentionally concurrent.
static PROVISIONING_ORDER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── Public types ──────────────────────────────────────────────

/// Result of allocating a dedicated IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedIp {
    pub id: Uuid,
    pub ip_address: String,
    pub hetzner_floating_ip_id: i64,
    pub region: String,
    pub rdns_hostname: Option<String>,
    pub warmup_day: i32,
    pub billing_status: String, // "included" or "pending_charge"
}

/// Current status of a dedicated IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedIpStatus {
    pub ip_address: String,
    pub warmup_day: i32,
    pub warmup_progress: f64,
    pub health: IpHealth,
    pub daily_limit: Option<u64>,
    pub warmup_started_at: DateTime<Utc>,
}

/// Health status of an IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpHealth {
    Healthy,
    Warming,
    Degraded,
    Disabled,
}

/// Errors from the IP provider.
#[derive(Debug, thiserror::Error)]
pub enum IpProviderError {
    #[error("no MTA servers available in region {region}")]
    NoAvailableServers { region: String },

    #[error("IP {ip} not found")]
    IpNotFound { ip: String },

    #[error("Hetzner API error: {0}")]
    HetznerApi(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("tenant {tenant_id} has reached dedicated IP limit ({limit})")]
    LimitReached { tenant_id: String, limit: i32 },

    #[error("plan does not include dedicated IP access")]
    PlanNotEligible,

    #[error("Hetzner not configured — set HETZNER_API_TOKEN")]
    NotConfigured,

    /// The state machine refused a step (skipped or out-of-order transition).
    #[error("invalid dedicated-IP state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    /// No verified domain exists, so no rDNS hostname can be set. Failing
    /// here avoids creating a provider resource that can never be published.
    #[error("tenant {tenant_id} has no verified domain — cannot configure rDNS")]
    NoVerifiedDomain { tenant_id: String },

    /// The floating IP could not be attached to an MTA server.
    #[error("failed to attach dedicated IP to MTA server: {0}")]
    AttachFailed(String),

    /// No MTA server is configured for attachment.
    #[error("no MTA server configured for floating-IP attachment — set HETZNER_MTA_SERVER_ID")]
    AttachTargetUnavailable,

    /// The provider set rDNS, but the PTR record did not confirm it.
    #[error("rDNS verification failed for {ip}: {reason}")]
    RdnsNotVerified { ip: String, reason: String },

    /// The provider returned an empty/blank IP address.
    #[error("provider returned an empty IP address")]
    EmptyProviderIp,

    /// Provider cleanup (delete) failed after a provisioning failure. The
    /// resource may still exist — the row is recorded as `cleanup_failed`.
    #[error("provider cleanup failed for {ip} (resource {provider_resource_id:?}): {reason}")]
    CompensationFailed {
        ip: String,
        provider_resource_id: Option<i64>,
        reason: String,
    },
}

impl From<sqlx::Error> for IpProviderError {
    fn from(e: sqlx::Error) -> Self {
        IpProviderError::Database(e.to_string())
    }
}

// ─── State machine ─────────────────────────────────────────────

/// Lifecycle states persisted in `dedicated_ips.status`.
///
/// The CHECK vocabulary is extended by migration 207; this enum is the
/// canonical Rust mirror and the only place transition rules live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedicatedIpState {
    /// Legacy (SES-era) status; not selectable.
    Pending,
    /// In-flight before a row can exist (see module docs).
    Provisioning,
    /// Provider floating IP exists and the row records it.
    Created,
    /// Floating IP is attached to an MTA server.
    Attached,
    /// rDNS was set and verified by an actual PTR lookup.
    RdnsReady,
    /// Selectable: warmup in progress.
    Warming,
    /// Selectable: warmup complete.
    Active,
    /// Existing operational hold; not selectable.
    Suspended,
    /// Existing schema vocabulary (021 create branch); not selectable.
    Cooldown,
    /// Terminal provisioning failure; provider cleanup succeeded.
    Failed,
    /// Terminal provisioning failure; provider cleanup FAILED and the
    /// resource may still exist. Loud and queryable.
    CleanupFailed,
    /// Release in progress; not selectable.
    Releasing,
    /// Released; not selectable.
    Retired,
}

impl DedicatedIpState {
    /// Every state in the vocabulary; used by table-driven fail-closed tests.
    pub const ALL: [DedicatedIpState; 13] = [
        DedicatedIpState::Pending,
        DedicatedIpState::Provisioning,
        DedicatedIpState::Created,
        DedicatedIpState::Attached,
        DedicatedIpState::RdnsReady,
        DedicatedIpState::Warming,
        DedicatedIpState::Active,
        DedicatedIpState::Suspended,
        DedicatedIpState::Cooldown,
        DedicatedIpState::Failed,
        DedicatedIpState::CleanupFailed,
        DedicatedIpState::Releasing,
        DedicatedIpState::Retired,
    ];

    /// Wire/DB representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            DedicatedIpState::Pending => "pending",
            DedicatedIpState::Provisioning => "provisioning",
            DedicatedIpState::Created => "created",
            DedicatedIpState::Attached => "attached",
            DedicatedIpState::RdnsReady => "rdns_ready",
            DedicatedIpState::Warming => "warming",
            DedicatedIpState::Active => "active",
            DedicatedIpState::Suspended => "suspended",
            DedicatedIpState::Cooldown => "cooldown",
            DedicatedIpState::Failed => "failed",
            DedicatedIpState::CleanupFailed => "cleanup_failed",
            DedicatedIpState::Releasing => "releasing",
            DedicatedIpState::Retired => "retired",
        }
    }

    /// Parse a status value. Unknown/hostile values return `None` — callers
    /// must fail closed, never guess.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == value)
    }

    /// The happy-path successor, one step at a time. `None` for every state
    /// that is not part of the provisioning chain.
    pub const fn next(self) -> Option<Self> {
        match self {
            DedicatedIpState::Provisioning => Some(DedicatedIpState::Created),
            DedicatedIpState::Created => Some(DedicatedIpState::Attached),
            DedicatedIpState::Attached => Some(DedicatedIpState::RdnsReady),
            DedicatedIpState::RdnsReady => Some(DedicatedIpState::Warming),
            DedicatedIpState::Warming => Some(DedicatedIpState::Active),
            _ => None,
        }
    }

    /// States eligible to carry sends, ignoring the warmup anchor.
    pub const fn is_selectable(self) -> bool {
        matches!(self, DedicatedIpState::Warming | DedicatedIpState::Active)
    }

    /// States an attempt can be failed from.
    pub const fn is_in_flight(self) -> bool {
        matches!(
            self,
            DedicatedIpState::Provisioning
                | DedicatedIpState::Created
                | DedicatedIpState::Attached
                | DedicatedIpState::RdnsReady
        )
    }

    /// Terminal states never transition again.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            DedicatedIpState::Failed | DedicatedIpState::CleanupFailed | DedicatedIpState::Retired
        )
    }

    /// Selectability INCLUDING the warmup anchor: a `warming` row without
    /// `warmup_started_at` is inconsistent and must not be selected (the
    /// worker keys daily admission on that column). `active` needs no anchor.
    pub fn is_selectable_with_anchor(self, warmup_started_at: Option<DateTime<Utc>>) -> bool {
        match self {
            DedicatedIpState::Warming => warmup_started_at.is_some(),
            DedicatedIpState::Active => true,
            _ => false,
        }
    }

    /// Fail-closed selectability from raw DB values (hostile status strings
    /// and NULL anchors both select nothing).
    pub fn parse_selectable(status: &str, warmup_started_at: Option<DateTime<Utc>>) -> bool {
        Self::parse(status)
            .map(|state| state.is_selectable_with_anchor(warmup_started_at))
            .unwrap_or(false)
    }
}

/// A refused transition. The message names both states so operators can see
/// exactly which step was skipped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateTransitionError {
    #[error("invalid dedicated-IP state transition {from} -> {to} (steps may not be skipped)")]
    Illegal {
        from: &'static str,
        to: &'static str,
    },
}

/// The one transition function. Rules:
/// * happy path advances exactly one step;
/// * an in-flight state may fail to `failed`/`cleanup_failed`;
/// * same-state is an idempotent no-op (resume);
/// * everything else — skipped steps, terminal resurrection, unknown
///   statuses (already rejected by [`DedicatedIpState::parse`]) — is refused.
pub fn transition(
    from: DedicatedIpState,
    to: DedicatedIpState,
) -> Result<DedicatedIpState, StateTransitionError> {
    if from == to {
        return Ok(to);
    }
    if from.next() == Some(to) {
        return Ok(to);
    }
    if from.is_in_flight()
        && matches!(
            to,
            DedicatedIpState::Failed | DedicatedIpState::CleanupFailed
        )
    {
        return Ok(to);
    }
    Err(StateTransitionError::Illegal {
        from: from.as_str(),
        to: to.as_str(),
    })
}

fn assert_transition(from: DedicatedIpState, to: DedicatedIpState) -> Result<(), IpProviderError> {
    transition(from, to)
        .map(|_| ())
        .map_err(|e| IpProviderError::InvalidStateTransition {
            from: e.from_state().to_string(),
            to: e.to_state().to_string(),
        })
}

impl StateTransitionError {
    fn from_state(&self) -> &'static str {
        match self {
            StateTransitionError::Illegal { from, .. } => from,
        }
    }

    fn to_state(&self) -> &'static str {
        match self {
            StateTransitionError::Illegal { to, .. } => to,
        }
    }
}

// ─── Ports (store / provider / verifier) ───────────────────────

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Plan gate result.
#[derive(Debug, Clone, Copy)]
struct PlanEligibility {
    allowed: bool,
    included_count: i32,
}

/// A dedicated_ips row in its first persisted state (`created`).
#[derive(Debug, Clone)]
struct NewDedicatedIp {
    id: Uuid,
    tenant_id: String,
    ip_address: String,
    region: String,
    provider_resource_id: i64,
    billing_status: String,
}

/// A terminal failure record. Upserted by id so it works both when the row
/// already exists (`created`+) and when the provider resource was created but
/// the initial insert failed.
#[derive(Debug, Clone)]
struct FailureRecord {
    id: Uuid,
    tenant_id: String,
    ip_address: String,
    region: String,
    provider_resource_id: Option<i64>,
    billing_status: String,
    status: DedicatedIpState,
    error_detail: String,
}

/// Persistence port. Every status write is a compare-and-swap that refuses
/// anything the pure state machine rejects.
trait ProvisioningStore: Send + Sync {
    fn load_plan<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> BoxFuture<'a, Result<PlanEligibility, IpProviderError>>;

    fn count_active<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> BoxFuture<'a, Result<i64, IpProviderError>>;

    /// The rDNS target for the tenant, if a verified domain exists.
    fn load_rdns_hostname<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, IpProviderError>>;

    fn insert_created(&self, row: NewDedicatedIp) -> BoxFuture<'_, Result<(), IpProviderError>>;

    fn mark_attached(
        &self,
        id: Uuid,
        server_id: i64,
    ) -> BoxFuture<'_, Result<bool, IpProviderError>>;

    fn mark_rdns_ready(
        &self,
        id: Uuid,
        hostname: String,
    ) -> BoxFuture<'_, Result<bool, IpProviderError>>;

    fn mark_warming(&self, id: Uuid) -> BoxFuture<'_, Result<bool, IpProviderError>>;

    /// Record a terminal failure (`failed` or `cleanup_failed`).
    fn record_failure(&self, record: FailureRecord)
        -> BoxFuture<'_, Result<bool, IpProviderError>>;
}

/// Provider resource returned by `create_floating_ip`.
#[derive(Debug, Clone)]
struct ProviderResource {
    id: i64,
    ip_address: String,
}

/// Provider port (Hetzner in production, recording fake in tests).
trait IpProviderOps: Send + Sync {
    fn create_floating_ip<'a>(
        &'a self,
        tenant_id: &'a str,
        location: &'a str,
    ) -> BoxFuture<'a, Result<ProviderResource, IpProviderError>>;

    fn assign_floating_ip(
        &self,
        resource_id: i64,
        server_id: i64,
    ) -> BoxFuture<'_, Result<(), IpProviderError>>;

    fn set_rdns<'a>(
        &'a self,
        resource_id: i64,
        ip_address: &'a str,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<(), IpProviderError>>;

    fn delete_floating_ip(&self, resource_id: i64) -> BoxFuture<'_, Result<(), IpProviderError>>;
}

/// Result of an actual reverse-DNS lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RdnsVerification {
    /// At least one PTR answer matches the expected hostname.
    Verified { ptr_names: Vec<String> },
    /// PTR answers exist but none match.
    Mismatch {
        ptr_names: Vec<String>,
        expected: String,
        reason: String,
    },
    /// The lookup could not be performed (resolver unavailable/timeout).
    /// MUST NOT be treated as success.
    LookupUnavailable { reason: String },
}

impl RdnsVerification {
    fn is_verified(&self) -> bool {
        matches!(self, RdnsVerification::Verified { .. })
    }

    fn failure_reason(&self) -> Option<String> {
        match self {
            RdnsVerification::Verified { .. } => None,
            RdnsVerification::Mismatch { reason, .. } => Some(reason.clone()),
            RdnsVerification::LookupUnavailable { reason } => {
                Some(format!("rDNS lookup unavailable: {reason}"))
            }
        }
    }
}

/// rDNS verification port. A successful provider API call is NOT evidence;
/// only this lookup is.
trait RdnsVerifier: Send + Sync {
    fn verify<'a>(
        &'a self,
        ip_address: &'a str,
        expected_hostname: &'a str,
    ) -> BoxFuture<'a, RdnsVerification>;
}

/// Everything the orchestrator needs for one attempt.
struct ProvisionRequest<'a> {
    tenant_id: &'a str,
    region: Option<&'a str>,
    default_location: &'a str,
    mta_server_id: Option<u64>,
}

// ─── Production adapters ───────────────────────────────────────

/// Postgres-backed [`ProvisioningStore`].
struct PgProvisioningStore<'a> {
    db: &'a PgPool,
}

async fn pg_load_plan(db: &PgPool, tenant_id: &str) -> Result<PlanEligibility, IpProviderError> {
    let row = sqlx::query_as::<_, (bool, i32)>(
        "SELECT
            COALESCE((p.features->>'dedicated_ip')::boolean, false),
            COALESCE((p.features->>'dedicated_ip_count')::int, 0)
         FROM tenants t
         LEFT JOIN plans p ON p.name = t.plan
         WHERE t.id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    Ok(match row {
        Some((allowed, count)) => PlanEligibility {
            allowed,
            included_count: count,
        },
        None => PlanEligibility {
            allowed: false,
            included_count: 0,
        },
    })
}

async fn pg_count_active(db: &PgPool, tenant_id: &str) -> Result<i64, IpProviderError> {
    let (count,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM dedicated_ips
         WHERE tenant_id = $1 AND status NOT IN ({})",
        non_occupying_status_list_sql()
    ))
    .bind(tenant_id)
    .fetch_one(db)
    .await?;
    Ok(count)
}

/// Upsert a terminal failure row. `link_provider_id=false` retries without the
/// Hetzner id when the unique constraint on `hetzner_floating_ip_id` is the
/// only thing blocking a loud record (the id then lives in the error text).
async fn upsert_failure_row(
    db: &PgPool,
    record: &FailureRecord,
    link_provider_id: bool,
) -> Result<u64, sqlx::Error> {
    let provider_id = if link_provider_id {
        record.provider_resource_id
    } else {
        None
    };
    let detail = if link_provider_id {
        record.error_detail.clone()
    } else {
        format!(
            "{} [provider resource {:?} not linked: uniqueness conflict]",
            record.error_detail, record.provider_resource_id
        )
    };

    let result = sqlx::query(
        "INSERT INTO dedicated_ips
         (id, tenant_id, ip_address, region, status, warmup_progress,
          hetzner_floating_ip_id, billing_status, allocated_at, created_at, updated_at,
          provisioning_error, provisioning_failed_at)
         VALUES ($1, $2, $3, $4, $5, 0.0, $6, $7, NOW(), NOW(), NOW(), $8, NOW())
         ON CONFLICT (id) DO UPDATE SET
             status = EXCLUDED.status,
             provisioning_error = EXCLUDED.provisioning_error,
             provisioning_failed_at = EXCLUDED.provisioning_failed_at,
             updated_at = NOW()
         WHERE dedicated_ips.status IN ('provisioning', 'created', 'attached', 'rdns_ready')",
    )
    .bind(record.id)
    .bind(&record.tenant_id)
    .bind(&record.ip_address)
    .bind(&record.region)
    .bind(record.status.as_str())
    .bind(provider_id)
    .bind(&record.billing_status)
    .bind(&detail)
    .execute(db)
    .await?;

    Ok(result.rows_affected())
}

impl ProvisioningStore for PgProvisioningStore<'_> {
    fn load_plan<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> BoxFuture<'a, Result<PlanEligibility, IpProviderError>> {
        Box::pin(pg_load_plan(self.db, tenant_id))
    }

    fn count_active<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> BoxFuture<'a, Result<i64, IpProviderError>> {
        Box::pin(pg_count_active(self.db, tenant_id))
    }

    fn load_rdns_hostname<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, IpProviderError>> {
        Box::pin(async move {
            let domain: Option<String> = sqlx::query_scalar(
                "SELECT name FROM domains
                   WHERE tenant_id = $1 AND verified = true
                 ORDER BY created_at LIMIT 1",
            )
            .bind(tenant_id)
            .fetch_optional(self.db)
            .await?;

            Ok(domain.map(|d| format!("mail.{d}")))
        })
    }

    fn insert_created(&self, row: NewDedicatedIp) -> BoxFuture<'_, Result<(), IpProviderError>> {
        Box::pin(async move {
            assert_transition(DedicatedIpState::Provisioning, DedicatedIpState::Created)?;
            sqlx::query(
                "INSERT INTO dedicated_ips
                 (id, tenant_id, ip_address, region, status, warmup_progress,
                  hetzner_floating_ip_id, billing_status, allocated_at, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'created', 0.0, $5, $6, NOW(), NOW(), NOW())",
            )
            .bind(row.id)
            .bind(&row.tenant_id)
            .bind(&row.ip_address)
            .bind(&row.region)
            .bind(row.provider_resource_id)
            .bind(&row.billing_status)
            .execute(self.db)
            .await?;
            Ok(())
        })
    }

    fn mark_attached(
        &self,
        id: Uuid,
        server_id: i64,
    ) -> BoxFuture<'_, Result<bool, IpProviderError>> {
        Box::pin(async move {
            assert_transition(DedicatedIpState::Created, DedicatedIpState::Attached)?;
            let result = sqlx::query(
                "UPDATE dedicated_ips
                 SET status = 'attached', hetzner_server_id = $2, updated_at = NOW()
                 WHERE id = $1 AND status = 'created'",
            )
            .bind(id)
            .bind(server_id)
            .execute(self.db)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn mark_rdns_ready(
        &self,
        id: Uuid,
        hostname: String,
    ) -> BoxFuture<'_, Result<bool, IpProviderError>> {
        Box::pin(async move {
            assert_transition(DedicatedIpState::Attached, DedicatedIpState::RdnsReady)?;
            let result = sqlx::query(
                "UPDATE dedicated_ips
                 SET status = 'rdns_ready', rdns_hostname = $2,
                     rdns_verified_at = NOW(), updated_at = NOW()
                 WHERE id = $1 AND status = 'attached'",
            )
            .bind(id)
            .bind(&hostname)
            .execute(self.db)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn mark_warming(&self, id: Uuid) -> BoxFuture<'_, Result<bool, IpProviderError>> {
        Box::pin(async move {
            assert_transition(DedicatedIpState::RdnsReady, DedicatedIpState::Warming)?;
            let result = sqlx::query(
                "UPDATE dedicated_ips
                 SET status = 'warming',
                     warmup_started_at = COALESCE(warmup_started_at, NOW()),
                     updated_at = NOW()
                 WHERE id = $1
                   AND status = 'rdns_ready'
                   AND rdns_hostname IS NOT NULL
                   AND rdns_verified_at IS NOT NULL",
            )
            .bind(id)
            .execute(self.db)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn record_failure(
        &self,
        record: FailureRecord,
    ) -> BoxFuture<'_, Result<bool, IpProviderError>> {
        Box::pin(async move {
            debug_assert!(
                matches!(
                    record.status,
                    DedicatedIpState::Failed | DedicatedIpState::CleanupFailed
                ),
                "record_failure only records terminal failure states"
            );

            match upsert_failure_row(self.db, &record, true).await {
                Ok(n) => Ok(n == 1),
                Err(e)
                    if e.as_database_error()
                        .map(|d| d.is_unique_violation())
                        .unwrap_or(false) =>
                {
                    match upsert_failure_row(self.db, &record, false).await {
                        Ok(n) => Ok(n == 1),
                        Err(e2) => Err(IpProviderError::Database(e2.to_string())),
                    }
                }
                Err(e) => Err(IpProviderError::Database(e.to_string())),
            }
        })
    }
}

/// Hetzner Cloud-backed [`IpProviderOps`].
struct HetznerOps<'a> {
    client: &'a Client,
    api_token: &'a str,
}

impl IpProviderOps for HetznerOps<'_> {
    fn create_floating_ip<'a>(
        &'a self,
        tenant_id: &'a str,
        location: &'a str,
    ) -> BoxFuture<'a, Result<ProviderResource, IpProviderError>> {
        Box::pin(async move {
            let mut labels = HashMap::new();
            labels.insert("tenant_id".to_string(), tenant_id.to_string());
            labels.insert("service".to_string(), "apexmail".to_string());
            labels.insert("type".to_string(), "dedicated_ip".to_string());

            let create_req = CreateFloatingIpRequest {
                ip_type: "ipv4".to_string(),
                home_location: location.to_string(),
                description: Some(format!("ApexMail dedicated IP for tenant {tenant_id}")),
                labels,
            };

            let resp = self
                .client
                .post(format!("{HETZNER_API_BASE}/floating_ips"))
                .bearer_auth(self.api_token)
                .json(&create_req)
                .send()
                .await
                .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

            if !resp.status().is_success() {
                let err = resp.text().await.unwrap_or_default();
                error!(tenant_id = %tenant_id, error = %err, "Hetzner floating IP creation failed");
                return Err(IpProviderError::HetznerApi(err));
            }

            let body: HetznerFloatingIpResponse = resp
                .json()
                .await
                .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

            debug!(tenant_id = %tenant_id, ip = %body.floating_ip.ip, id = body.floating_ip.id, "Created Hetzner floating IP");

            Ok(ProviderResource {
                id: body.floating_ip.id as i64,
                ip_address: body.floating_ip.ip,
            })
        })
    }

    fn assign_floating_ip(
        &self,
        resource_id: i64,
        server_id: i64,
    ) -> BoxFuture<'_, Result<(), IpProviderError>> {
        Box::pin(async move {
            let assign_req = AssignFloatingIpRequest {
                server: server_id as u64,
            };
            let resp = self
                .client
                .post(format!(
                    "{HETZNER_API_BASE}/floating_ips/{resource_id}/actions/assign"
                ))
                .bearer_auth(self.api_token)
                .json(&assign_req)
                .send()
                .await
                .map_err(|e| IpProviderError::AttachFailed(e.to_string()))?;

            if !resp.status().is_success() {
                let err = resp.text().await.unwrap_or_default();
                return Err(IpProviderError::AttachFailed(err));
            }
            debug!(resource_id, server_id, "Attached floating IP to MTA server");
            Ok(())
        })
    }

    fn set_rdns<'a>(
        &'a self,
        resource_id: i64,
        ip_address: &'a str,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<(), IpProviderError>> {
        Box::pin(async move {
            let req = UpdateRdnsRequest {
                ip: ip_address.to_string(),
                dns_ptr: hostname.to_string(),
            };
            let resp = self
                .client
                .post(format!(
                    "{HETZNER_API_BASE}/floating_ips/{resource_id}/actions/change_dns_ptr"
                ))
                .bearer_auth(self.api_token)
                .json(&req)
                .send()
                .await
                .map_err(|e| IpProviderError::HetznerApi(format!("rDNS request failed: {e}")))?;

            if !resp.status().is_success() {
                let err = resp.text().await.unwrap_or_default();
                return Err(IpProviderError::HetznerApi(format!(
                    "rDNS change_dns_ptr failed: {err}"
                )));
            }
            Ok(())
        })
    }

    fn delete_floating_ip(&self, resource_id: i64) -> BoxFuture<'_, Result<(), IpProviderError>> {
        Box::pin(async move {
            let resp = self
                .client
                .delete(format!("{HETZNER_API_BASE}/floating_ips/{resource_id}"))
                .bearer_auth(self.api_token)
                .send()
                .await
                .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

            // 404 = already gone; cleanup is satisfied.
            if !resp.status().is_success() && resp.status().as_u16() != 404 {
                let err = resp.text().await.unwrap_or_default();
                return Err(IpProviderError::HetznerApi(format!(
                    "floating IP delete failed: {err}"
                )));
            }
            Ok(())
        })
    }
}

/// Production rDNS verifier: an actual PTR lookup through the workspace
/// resolver. A resolver that cannot be built is `LookupUnavailable`, which the
/// state machine treats exactly like a failure (never as success).
struct DnsRdnsVerifier;

fn normalize_ptr(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl RdnsVerifier for DnsRdnsVerifier {
    fn verify<'a>(
        &'a self,
        ip_address: &'a str,
        expected_hostname: &'a str,
    ) -> BoxFuture<'a, RdnsVerification> {
        Box::pin(async move {
            let ip: std::net::IpAddr = match ip_address.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    return RdnsVerification::Mismatch {
                        ptr_names: Vec::new(),
                        expected: expected_hostname.to_string(),
                        reason: format!("provider returned an unparseable IP {ip_address:?}: {e}"),
                    };
                }
            };

            let lookup = match dns_resolver::DnsLookup::new() {
                Ok(lookup) => lookup,
                Err(e) => {
                    return RdnsVerification::LookupUnavailable {
                        reason: e.to_string(),
                    };
                }
            };

            match lookup.reverse_lookup(ip).await {
                Ok(ptr_names) => {
                    let expected = normalize_ptr(expected_hostname);
                    if ptr_names.iter().any(|n| normalize_ptr(n) == expected) {
                        RdnsVerification::Verified { ptr_names }
                    } else {
                        RdnsVerification::Mismatch {
                            reason: format!(
                                "PTR {ptr_names:?} does not match expected {expected_hostname}"
                            ),
                            ptr_names,
                            expected: expected_hostname.to_string(),
                        }
                    }
                }
                Err(e) => RdnsVerification::LookupUnavailable {
                    reason: e.to_string(),
                },
            }
        })
    }
}

// ─── Orchestrator ──────────────────────────────────────────────

/// Everything needed to compensate a post-provider-creation failure.
#[derive(Debug, Clone, Copy)]
struct FailureCtx<'a> {
    id: Uuid,
    tenant_id: &'a str,
    region: &'a str,
    ip_address: &'a str,
    provider_resource_id: i64,
    billing_status: &'a str,
}

/// Delete the provider resource and record the terminal state. Returns
/// `Err(CompensationFailed)` when the delete itself failed; `Ok(())` means the
/// external resource is gone and the caller should surface its own cause.
async fn cleanup_and_record<P, S>(
    provider: &P,
    store: &S,
    ctx: FailureCtx<'_>,
    cause: String,
) -> Result<(), IpProviderError>
where
    P: IpProviderOps + ?Sized,
    S: ProvisioningStore + ?Sized,
{
    let cleanup = provider.delete_floating_ip(ctx.provider_resource_id).await;
    let (status, detail) = match &cleanup {
        Ok(()) => (
            DedicatedIpState::Failed,
            format!(
                "{cause}; provider resource {} deleted",
                ctx.provider_resource_id
            ),
        ),
        Err(e) => (
            DedicatedIpState::CleanupFailed,
            format!(
                "{cause}; PROVIDER CLEANUP FAILED for resource {}: {e}",
                ctx.provider_resource_id
            ),
        ),
    };

    let record = FailureRecord {
        id: ctx.id,
        tenant_id: ctx.tenant_id.to_string(),
        ip_address: ctx.ip_address.to_string(),
        region: ctx.region.to_string(),
        provider_resource_id: Some(ctx.provider_resource_id),
        billing_status: ctx.billing_status.to_string(),
        status,
        error_detail: detail.clone(),
    };

    match store.record_failure(record).await {
        Ok(true) => {
            if status == DedicatedIpState::CleanupFailed {
                error!(
                    tenant_id = %ctx.tenant_id,
                    ip = %ctx.ip_address,
                    provider_resource_id = ctx.provider_resource_id,
                    error = %detail,
                    "dedicated IP provider cleanup failed; orphaned resource recorded as cleanup_failed"
                );
            } else {
                warn!(
                    tenant_id = %ctx.tenant_id,
                    ip = %ctx.ip_address,
                    error = %detail,
                    "dedicated IP provisioning failed after provider creation; provider resource released"
                );
            }
        }
        Ok(false) => {
            error!(
                tenant_id = %ctx.tenant_id,
                provider_resource_id = ctx.provider_resource_id,
                error = %detail,
                "dedicated IP failure state write was refused; investigate this attempt"
            );
        }
        Err(record_err) => {
            // The DB is not cooperating; the identifiers below are the only
            // durable record of the provider resource.
            error!(
                tenant_id = %ctx.tenant_id,
                ip = %ctx.ip_address,
                provider_resource_id = ctx.provider_resource_id,
                cleanup_failed = (status == DedicatedIpState::CleanupFailed),
                record_error = %record_err,
                error = %detail,
                "COULD NOT RECORD dedicated IP provisioning failure state — search logs for this tenant and provider id"
            );
        }
    }

    if status == DedicatedIpState::CleanupFailed {
        Err(IpProviderError::CompensationFailed {
            ip: ctx.ip_address.to_string(),
            provider_resource_id: Some(ctx.provider_resource_id),
            reason: detail,
        })
    } else {
        Ok(())
    }
}

/// Surface the original error when cleanup succeeded, or the
/// `CompensationFailed` error when the external resource may still exist.
async fn surface_failure<P, S>(
    provider: &P,
    store: &S,
    ctx: FailureCtx<'_>,
    cause: String,
    original: IpProviderError,
) -> IpProviderError
where
    P: IpProviderOps + ?Sized,
    S: ProvisioningStore + ?Sized,
{
    match cleanup_and_record(provider, store, ctx, cause).await {
        Ok(()) => original,
        Err(compensation) => compensation,
    }
}

/// Run one provisioning attempt through the state machine.
///
/// Sequence: plan gate → count gate → verified-domain gate → provider create →
/// row (`created`) → attach → `attached` → rDNS set → PTR lookup → `rdns_ready`
/// → `warming`. Every failure after the provider create is compensated.
async fn run_provisioning<P, S, V>(
    provider: &P,
    store: &S,
    verifier: &V,
    req: &ProvisionRequest<'_>,
) -> Result<AllocatedIp, IpProviderError>
where
    P: IpProviderOps + ?Sized,
    S: ProvisioningStore + ?Sized,
    V: RdnsVerifier + ?Sized,
{
    // Serialize attempts in this process. Billing fires concurrent requests
    // intentionally, so this is ordering, not dedup (see module docs).
    let _serial = PROVISIONING_ORDER.lock().await;

    let plan = store.load_plan(req.tenant_id).await?;
    if !plan.allowed {
        return Err(IpProviderError::PlanNotEligible);
    }

    let active_count = store.count_active(req.tenant_id).await?;
    let hard_cap = if plan.included_count >= 10 {
        25
    } else {
        plan.included_count.max(5)
    };
    if active_count >= hard_cap as i64 {
        return Err(IpProviderError::LimitReached {
            tenant_id: req.tenant_id.to_string(),
            limit: hard_cap,
        });
    }

    // No verified domain → no rDNS target. Fail before spending provider
    // money rather than create an IP that can never be published.
    let hostname = match store.load_rdns_hostname(req.tenant_id).await? {
        Some(h) => h,
        None => {
            return Err(IpProviderError::NoVerifiedDomain {
                tenant_id: req.tenant_id.to_string(),
            });
        }
    };

    let location = req.region.unwrap_or(req.default_location);
    let resource = provider.create_floating_ip(req.tenant_id, location).await?;

    let ip_address = resource.ip_address.trim().to_string();
    let id = Uuid::new_v4();
    let billing_status = if active_count < plan.included_count as i64 {
        "included"
    } else {
        "pending_charge"
    }
    .to_string();

    let fail_ctx = FailureCtx {
        id,
        tenant_id: req.tenant_id,
        region: location,
        ip_address: &ip_address,
        provider_resource_id: resource.id,
        billing_status: &billing_status,
    };

    // Hostile provider output: an empty address can never be published.
    if ip_address.is_empty() {
        return Err(surface_failure(
            provider,
            store,
            fail_ctx,
            "provider returned an empty IP address".to_string(),
            IpProviderError::EmptyProviderIp,
        )
        .await);
    }

    assert_transition(DedicatedIpState::Provisioning, DedicatedIpState::Created)?;
    if let Err(e) = store
        .insert_created(NewDedicatedIp {
            id,
            tenant_id: req.tenant_id.to_string(),
            ip_address: ip_address.clone(),
            region: location.to_string(),
            provider_resource_id: resource.id,
            billing_status: billing_status.clone(),
        })
        .await
    {
        let cause = format!("database write failed after provider creation: {e}");
        return Err(surface_failure(provider, store, fail_ctx, cause, e).await);
    }

    // Attach is mandatory: an unattached floating IP cannot carry mail.
    let server_id = match req.mta_server_id {
        Some(server_id) => server_id as i64,
        None => {
            return Err(surface_failure(
                provider,
                store,
                fail_ctx,
                "no MTA server configured for attachment".to_string(),
                IpProviderError::AttachTargetUnavailable,
            )
            .await);
        }
    };

    if let Err(e) = provider.assign_floating_ip(resource.id, server_id).await {
        let cause = format!("attach failed: {e}");
        return Err(surface_failure(provider, store, fail_ctx, cause, e).await);
    }

    match store.mark_attached(id, server_id).await {
        Ok(true) => {}
        Ok(false) => {
            let cause = "state machine refused created -> attached".to_string();
            let original = IpProviderError::InvalidStateTransition {
                from: DedicatedIpState::Created.as_str().to_string(),
                to: DedicatedIpState::Attached.as_str().to_string(),
            };
            return Err(surface_failure(provider, store, fail_ctx, cause, original).await);
        }
        Err(e) => {
            let cause = format!("database write failed after attach: {e}");
            return Err(surface_failure(provider, store, fail_ctx, cause, e).await);
        }
    }

    if let Err(e) = provider.set_rdns(resource.id, &ip_address, &hostname).await {
        let cause = format!("rDNS set failed: {e}");
        return Err(surface_failure(provider, store, fail_ctx, cause, e).await);
    }

    // rDNS must be VERIFIED by a lookup; a provider 2xx is not evidence.
    let verification = verifier.verify(&ip_address, &hostname).await;
    if !verification.is_verified() {
        let reason = verification
            .failure_reason()
            .unwrap_or_else(|| "rDNS verification failed".to_string());
        let cause = format!("rDNS verification failed: {reason}");
        let original = IpProviderError::RdnsNotVerified {
            ip: ip_address.clone(),
            reason,
        };
        return Err(surface_failure(provider, store, fail_ctx, cause, original).await);
    }

    match store.mark_rdns_ready(id, hostname.clone()).await {
        Ok(true) => {}
        Ok(false) => {
            let cause = "state machine refused attached -> rdns_ready".to_string();
            let original = IpProviderError::InvalidStateTransition {
                from: DedicatedIpState::Attached.as_str().to_string(),
                to: DedicatedIpState::RdnsReady.as_str().to_string(),
            };
            return Err(surface_failure(provider, store, fail_ctx, cause, original).await);
        }
        Err(e) => {
            let cause = format!("database write failed after rDNS verification: {e}");
            return Err(surface_failure(provider, store, fail_ctx, cause, e).await);
        }
    }

    match store.mark_warming(id).await {
        Ok(true) => {}
        Ok(false) => {
            let cause = "state machine refused rdns_ready -> warming".to_string();
            let original = IpProviderError::InvalidStateTransition {
                from: DedicatedIpState::RdnsReady.as_str().to_string(),
                to: DedicatedIpState::Warming.as_str().to_string(),
            };
            return Err(surface_failure(provider, store, fail_ctx, cause, original).await);
        }
        Err(e) => {
            let cause = format!("database write failed while starting warmup: {e}");
            return Err(surface_failure(provider, store, fail_ctx, cause, e).await);
        }
    }

    info!(
        id = %id,
        ip = %ip_address,
        tenant_id = %req.tenant_id,
        billing = %billing_status,
        "Dedicated IP provisioned through attached+verified rDNS; status=warming"
    );

    Ok(AllocatedIp {
        id,
        ip_address,
        hetzner_floating_ip_id: resource.id,
        region: location.to_string(),
        rdns_hostname: Some(hostname),
        warmup_day: 0,
        billing_status,
    })
}

// ─── Hetzner API types (private) ───────────────────────────────

#[derive(Debug, Deserialize)]
struct HetznerFloatingIpResponse {
    floating_ip: HetznerFloatingIp,
}

#[derive(Debug, Deserialize)]
struct HetznerFloatingIp {
    id: u64,
    ip: String,
}

#[derive(Debug, Serialize)]
struct CreateFloatingIpRequest {
    #[serde(rename = "type")]
    ip_type: String,
    home_location: String,
    description: Option<String>,
    labels: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct AssignFloatingIpRequest {
    server: u64,
}

#[derive(Debug, Serialize)]
struct UpdateRdnsRequest {
    ip: String,
    dns_ptr: String,
}

// ─── Provider ──────────────────────────────────────────────────

/// Dedicated IP provider backed exclusively by Hetzner Cloud.
/// There is no SES dedicated-IP alternative. SES is used **only** for the
/// shared IP pool.
pub struct DedicatedIpProvider {
    client: Client,
    api_token: String,
    db: PgPool,
    /// Default Hetzner location for new IPs (e.g., "fsn1", "nbg1", "hel1").
    default_location: String,
    /// MTA server ID to assign floating IPs to. `None` means attachment is
    /// impossible: provisioning fails closed and releases the floating IP
    /// rather than publishing an unattached address.
    mta_server_id: Option<u64>,
}

impl DedicatedIpProvider {
    /// Create a new provider. Fails (instead of panicking) if the HTTP client
    /// cannot be constructed.
    pub fn new(
        api_token: String,
        db: PgPool,
        default_location: String,
        mta_server_id: Option<u64>,
    ) -> Result<Self, IpProviderError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                IpProviderError::HetznerApi(format!("failed to build HTTP client: {e}"))
            })?;

        Ok(Self {
            client,
            api_token,
            db,
            default_location,
            mta_server_id,
        })
    }

    /// Create from environment. Returns `None` if `HETZNER_API_TOKEN` is unset
    /// or the HTTP client cannot be built.
    pub fn from_env(db: PgPool) -> Option<Self> {
        let api_token = std::env::var("HETZNER_API_TOKEN").ok()?;
        let default_location =
            std::env::var("HETZNER_DEFAULT_LOCATION").unwrap_or_else(|_| "fsn1".to_string());
        let mta_server_id = std::env::var("HETZNER_MTA_SERVER_ID")
            .ok()
            .and_then(|s| s.parse().ok());

        match Self::new(api_token, db, default_location, mta_server_id) {
            Ok(provider) => Some(provider),
            Err(e) => {
                error!(error = %e, "dedicated IP provisioning disabled: HTTP client build failed");
                None
            }
        }
    }

    // ── Plan gating ────────────────────────────────────────────

    /// Check whether the tenant's plan allows dedicated IPs.
    /// Returns `(allowed, included_count)`.
    pub async fn check_plan_eligibility(
        &self,
        tenant_id: &str,
    ) -> Result<(bool, i32), IpProviderError> {
        let plan = pg_load_plan(&self.db, tenant_id).await?;
        Ok((plan.allowed, plan.included_count))
    }

    /// Count dedicated IPs occupying the tenant's allowance.
    pub async fn count_active_ips(&self, tenant_id: &str) -> Result<i64, IpProviderError> {
        pg_count_active(&self.db, tenant_id).await
    }

    // ── Allocation ─────────────────────────────────────────────

    /// Allocate a new dedicated IP for a tenant via Hetzner Cloud.
    ///
    /// Runs the state machine in `crate::ip_provider`:
    /// `provisioning → created → attached → rdns_ready → warming`, with
    /// provider cleanup on every post-create failure. Only `warming`/`active`
    /// rows are ever selected for sending.
    pub async fn allocate_ip(
        &self,
        tenant_id: &str,
        region: Option<&str>,
    ) -> Result<AllocatedIp, IpProviderError> {
        let store = PgProvisioningStore { db: &self.db };
        let ops = HetznerOps {
            client: &self.client,
            api_token: &self.api_token,
        };
        let verifier = DnsRdnsVerifier;
        let req = ProvisionRequest {
            tenant_id,
            region,
            default_location: &self.default_location,
            mta_server_id: self.mta_server_id,
        };

        run_provisioning(&ops, &store, &verifier, &req).await
    }

    // ── Release ────────────────────────────────────────────────

    /// Release a dedicated IP: delete the Hetzner floating IP and retire the
    /// DB record.
    /// If this was the tenant's last dedicated IP, the routing cache trigger
    /// flips them back to SES shared sending automatically.
    pub async fn release_ip(
        &self,
        dedicated_ip_id: Uuid,
        tenant_id: &str,
    ) -> Result<(), IpProviderError> {
        let row: Option<(String, Option<i64>)> = sqlx::query_as(
            "SELECT ip_address, hetzner_floating_ip_id FROM dedicated_ips
             WHERE id = $1 AND tenant_id = $2 AND status NOT IN ('retired', 'releasing')",
        )
        .bind(dedicated_ip_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address, hetzner_id) = row.ok_or_else(|| IpProviderError::IpNotFound {
            ip: dedicated_ip_id.to_string(),
        })?;

        // Delete from Hetzner
        if let Some(hid) = hetzner_id {
            let resp = self
                .client
                .delete(format!("{HETZNER_API_BASE}/floating_ips/{hid}"))
                .bearer_auth(&self.api_token)
                .send()
                .await
                .map_err(|e| IpProviderError::HetznerApi(e.to_string()))?;

            if !resp.status().is_success() && resp.status().as_u16() != 404 {
                let err = resp.text().await.unwrap_or_default();
                warn!(ip = %ip_address, error = %err, "Hetzner delete failed (continuing)");
            }
        }

        // Retire DB record
        sqlx::query(
            "UPDATE dedicated_ips
             SET status = 'retired',
                 billing_status = CASE
                     WHEN billing_status IN ('active', 'pending_charge') THEN 'pending_cancel'
                     ELSE billing_status
                 END,
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(dedicated_ip_id)
        .execute(&self.db)
        .await?;

        // ⚡ If this was the last IP, the trigger flips the tenant back to SES.

        info!(id = %dedicated_ip_id, ip = %ip_address, tenant_id = %tenant_id, "Dedicated IP released");
        Ok(())
    }

    // ── Warmup ─────────────────────────────────────────────────

    /// Start or resume warmup for a dedicated IP.
    ///
    /// Promotion to `warming` requires verified rDNS (`rdns_ready`); resuming
    /// an existing `warming` row requires its warmup anchor. Every other
    /// status is refused — the state machine is the single authority.
    pub async fn start_warmup(
        &self,
        dedicated_ip_id: Uuid,
        tenant_id: &str,
    ) -> Result<DedicatedIpStatus, IpProviderError> {
        assert_transition(DedicatedIpState::RdnsReady, DedicatedIpState::Warming)?;

        let row: Option<(String, f64, DateTime<Utc>)> = sqlx::query_as(
            "UPDATE dedicated_ips
             SET status = 'warming',
                 warmup_started_at = COALESCE(warmup_started_at, NOW()),
                 updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2
               AND (
                    (status = 'rdns_ready'
                     AND rdns_hostname IS NOT NULL
                     AND rdns_verified_at IS NOT NULL)
                 OR (status = 'warming' AND warmup_started_at IS NOT NULL)
               )
             RETURNING ip_address, warmup_progress, warmup_started_at",
        )
        .bind(dedicated_ip_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let (ip_address, progress, warmup_started_at) = match row {
            Some(row) => row,
            None => {
                // Distinguish "no such IP" from "wrong state" so the API can
                // return 404 vs 409.
                let current: Option<(String,)> = sqlx::query_as(
                    "SELECT status FROM dedicated_ips WHERE id = $1 AND tenant_id = $2",
                )
                .bind(dedicated_ip_id)
                .bind(tenant_id)
                .fetch_optional(&self.db)
                .await?;
                return match current {
                    Some((status,)) => Err(IpProviderError::InvalidStateTransition {
                        from: status,
                        to: DedicatedIpState::Warming.as_str().to_string(),
                    }),
                    None => Err(IpProviderError::IpNotFound {
                        ip: dedicated_ip_id.to_string(),
                    }),
                };
            }
        };

        let warmup_day = self.get_warmup_day(dedicated_ip_id).await?;
        let daily_limit = warmup_schedule::limit_for_day(warmup_day as u32);

        info!(id = %dedicated_ip_id, ip = %ip_address, day = warmup_day, limit = daily_limit, "Warmup started");

        Ok(DedicatedIpStatus {
            ip_address,
            warmup_day,
            warmup_progress: progress,
            health: IpHealth::Warming,
            daily_limit: Some(daily_limit),
            warmup_started_at,
        })
    }

    async fn get_warmup_day(&self, id: Uuid) -> Result<i32, IpProviderError> {
        let day: Option<(i32,)> = sqlx::query_as(
            "SELECT EXTRACT(DAY FROM NOW() - warmup_started_at)::int
             FROM dedicated_ips WHERE id = $1 AND warmup_started_at IS NOT NULL",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?;
        Ok(day.map(|(d,)| d).unwrap_or(0))
    }

    /// Periodic job: update warmup progress, graduate IPs after the full
    /// warmup period. Graduation goes through the transition guard
    /// (`warming → active`) and the CAS update requires the warmup anchor.
    pub async fn tick_warmup(&self) -> Result<u32, IpProviderError> {
        assert_transition(DedicatedIpState::Warming, DedicatedIpState::Active)?;

        let candidates: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM dedicated_ips
             WHERE status = 'warming' AND warmup_started_at IS NOT NULL
               AND EXTRACT(DAY FROM NOW() - warmup_started_at) >= $1",
        )
        .bind(warmup_schedule::FULL_WARMUP_DAYS as i32)
        .fetch_all(&self.db)
        .await?;

        let mut graduated = 0u32;
        for (id,) in candidates {
            let result = sqlx::query(
                "UPDATE dedicated_ips
                 SET status = 'active', warmup_progress = 1.0,
                     warmup_completed_at = NOW(), updated_at = NOW()
                 WHERE id = $1 AND status = 'warming' AND warmup_started_at IS NOT NULL",
            )
            .bind(id)
            .execute(&self.db)
            .await?;
            if result.rows_affected() == 1 {
                graduated += 1;
            }
        }

        let updated = sqlx::query(
            "UPDATE dedicated_ips
             SET warmup_progress = LEAST(
                     EXTRACT(DAY FROM NOW() - warmup_started_at) / $1::double precision,
                     1.0
                 ),
                 updated_at = NOW()
             WHERE status = 'warming' AND warmup_started_at IS NOT NULL",
        )
        .bind(warmup_schedule::FULL_WARMUP_DAYS as f64)
        .execute(&self.db)
        .await?
        .rows_affected();

        if graduated > 0 {
            info!(graduated = graduated, "IPs graduated from warmup → active");
        }
        Ok(graduated + updated as u32)
    }

    // ── Helpers ─────────────────────────────────────────────────

    /// List dedicated IPs for a tenant (including terminal/failure rows so
    /// operators can see the reconciliation worklist).
    pub async fn list_tenant_ips(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AllocatedIp>, IpProviderError> {
        let rows: Vec<(
            Uuid,
            String,
            Option<i64>,
            String,
            Option<String>,
            i32,
            String,
        )> = sqlx::query_as(
            "SELECT id, ip_address, hetzner_floating_ip_id, region, rdns_hostname,
                        EXTRACT(DAY FROM NOW() - COALESCE(warmup_started_at, created_at))::int,
                        COALESCE(billing_status, 'included')
                 FROM dedicated_ips
                 WHERE tenant_id = $1 AND status NOT IN ('retired', 'releasing')
                 ORDER BY created_at",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, ip, hid, region, rdns, day, billing)| AllocatedIp {
                id,
                ip_address: ip,
                hetzner_floating_ip_id: hid.unwrap_or(0),
                region,
                rdns_hostname: rdns,
                warmup_day: day,
                billing_status: billing,
            })
            .collect())
    }
}

// ─── Warmup schedule ───────────────────────────────────────────

/// Canonical dedicated-IP warmup schedule shared with billing and outbound delivery.
pub use mail_common::warmup as warmup_schedule;

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ── Fakes ──────────────────────────────────────────────────

    #[derive(Debug, Clone, PartialEq)]
    enum ProviderCall {
        Create { tenant_id: String, location: String },
        Assign { resource_id: i64, server_id: i64 },
        SetRdns { resource_id: i64, hostname: String },
        Delete { resource_id: i64 },
    }

    struct FakeProvider {
        state: Mutex<FakeProviderState>,
    }

    struct FakeProviderState {
        calls: Vec<ProviderCall>,
        fail_all: bool,
        fail_create: Option<String>,
        fail_assign: Option<String>,
        fail_set_rdns: Option<String>,
        fail_delete: Option<String>,
        next_resource_id: i64,
        resource_ip: String,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                state: Mutex::new(FakeProviderState {
                    calls: Vec::new(),
                    fail_all: false,
                    fail_create: None,
                    fail_assign: None,
                    fail_set_rdns: None,
                    fail_delete: None,
                    next_resource_id: 1000,
                    resource_ip: "203.0.113.10".to_string(),
                }),
            }
        }

        fn calls(&self) -> Vec<ProviderCall> {
            self.state.lock().unwrap().calls.clone()
        }

        fn delete_calls(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| matches!(c, ProviderCall::Delete { .. }))
                .count()
        }

        fn create_calls(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| matches!(c, ProviderCall::Create { .. }))
                .count()
        }
    }

    impl IpProviderOps for FakeProvider {
        fn create_floating_ip<'a>(
            &'a self,
            tenant_id: &'a str,
            location: &'a str,
        ) -> BoxFuture<'a, Result<ProviderResource, IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.calls.push(ProviderCall::Create {
                    tenant_id: tenant_id.to_string(),
                    location: location.to_string(),
                });
                if state.fail_all {
                    return Err(IpProviderError::HetznerApi("provider unavailable".into()));
                }
                if let Some(reason) = state.fail_create.clone() {
                    return Err(IpProviderError::HetznerApi(reason));
                }
                let id = state.next_resource_id;
                state.next_resource_id += 1;
                Ok(ProviderResource {
                    id,
                    ip_address: state.resource_ip.clone(),
                })
            })
        }

        fn assign_floating_ip(
            &self,
            resource_id: i64,
            server_id: i64,
        ) -> BoxFuture<'_, Result<(), IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.calls.push(ProviderCall::Assign {
                    resource_id,
                    server_id,
                });
                if state.fail_all {
                    return Err(IpProviderError::AttachFailed("provider unavailable".into()));
                }
                if let Some(reason) = state.fail_assign.clone() {
                    return Err(IpProviderError::AttachFailed(reason));
                }
                Ok(())
            })
        }

        fn set_rdns<'a>(
            &'a self,
            resource_id: i64,
            _ip_address: &'a str,
            hostname: &'a str,
        ) -> BoxFuture<'a, Result<(), IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.calls.push(ProviderCall::SetRdns {
                    resource_id,
                    hostname: hostname.to_string(),
                });
                if state.fail_all {
                    return Err(IpProviderError::HetznerApi("provider unavailable".into()));
                }
                if let Some(reason) = state.fail_set_rdns.clone() {
                    return Err(IpProviderError::HetznerApi(reason));
                }
                Ok(())
            })
        }

        fn delete_floating_ip(
            &self,
            resource_id: i64,
        ) -> BoxFuture<'_, Result<(), IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.calls.push(ProviderCall::Delete { resource_id });
                if state.fail_all {
                    return Err(IpProviderError::HetznerApi("provider unavailable".into()));
                }
                if let Some(reason) = state.fail_delete.clone() {
                    return Err(IpProviderError::HetznerApi(reason));
                }
                Ok(())
            })
        }
    }

    #[derive(Debug, Clone)]
    struct FakeRow {
        id: Uuid,
        status: String,
        warmup_started_at: Option<DateTime<Utc>>,
        provider_resource_id: Option<i64>,
        error_detail: Option<String>,
    }

    struct FakeStore {
        state: Mutex<FakeStoreState>,
    }

    struct FakeStoreState {
        allowed: bool,
        included_count: i32,
        hostname: Option<String>,
        rows: Vec<FakeRow>,
        insert_attempts: usize,
        fail_insert_created_after: Option<usize>,
        fail_insert_created: Option<String>,
        fail_mark_attached: Option<String>,
        mark_attached_refuses: bool,
        fail_mark_rdns_ready: Option<String>,
        fail_mark_warming: Option<String>,
        fail_record_failure: Option<String>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                state: Mutex::new(FakeStoreState {
                    allowed: true,
                    included_count: 5,
                    hostname: Some("mail.example.com".to_string()),
                    rows: Vec::new(),
                    insert_attempts: 0,
                    fail_insert_created_after: None,
                    fail_insert_created: None,
                    fail_mark_attached: None,
                    mark_attached_refuses: false,
                    fail_mark_rdns_ready: None,
                    fail_mark_warming: None,
                    fail_record_failure: None,
                }),
            }
        }

        fn rows(&self) -> Vec<FakeRow> {
            self.state.lock().unwrap().rows.clone()
        }

        /// Selectable rows, using the production predicate (warmup anchor
        /// required for `warming`).
        fn selectable_rows(&self) -> Vec<FakeRow> {
            self.rows()
                .into_iter()
                .filter(|r| DedicatedIpState::parse_selectable(&r.status, r.warmup_started_at))
                .collect()
        }
    }

    impl ProvisioningStore for FakeStore {
        fn load_plan<'a>(
            &'a self,
            _tenant_id: &'a str,
        ) -> BoxFuture<'a, Result<PlanEligibility, IpProviderError>> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                Ok(PlanEligibility {
                    allowed: state.allowed,
                    included_count: state.included_count,
                })
            })
        }

        fn count_active<'a>(
            &'a self,
            _tenant_id: &'a str,
        ) -> BoxFuture<'a, Result<i64, IpProviderError>> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                let count = state
                    .rows
                    .iter()
                    .filter(|r| {
                        !matches!(
                            r.status.as_str(),
                            "retired" | "releasing" | "failed" | "cleanup_failed"
                        )
                    })
                    .count() as i64;
                Ok(count)
            })
        }

        fn load_rdns_hostname<'a>(
            &'a self,
            _tenant_id: &'a str,
        ) -> BoxFuture<'a, Result<Option<String>, IpProviderError>> {
            Box::pin(async move { Ok(self.state.lock().unwrap().hostname.clone()) })
        }

        fn insert_created(
            &self,
            row: NewDedicatedIp,
        ) -> BoxFuture<'_, Result<(), IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                let attempt = state.insert_attempts;
                state.insert_attempts += 1;
                if let Some(fail_after) = state.fail_insert_created_after {
                    if attempt >= fail_after {
                        return Err(IpProviderError::Database(
                            "simulated insert failure".to_string(),
                        ));
                    }
                }
                if let Some(reason) = state.fail_insert_created.clone() {
                    return Err(IpProviderError::Database(reason));
                }
                state.rows.push(FakeRow {
                    id: row.id,
                    status: DedicatedIpState::Created.as_str().to_string(),
                    warmup_started_at: None,
                    provider_resource_id: Some(row.provider_resource_id),
                    error_detail: None,
                });
                Ok(())
            })
        }

        fn mark_attached(
            &self,
            id: Uuid,
            _server_id: i64,
        ) -> BoxFuture<'_, Result<bool, IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(reason) = state.fail_mark_attached.clone() {
                    return Err(IpProviderError::Database(reason));
                }
                if state.mark_attached_refuses {
                    return Ok(false);
                }
                let Some(row) = state.rows.iter_mut().find(|r| r.id == id) else {
                    return Ok(false);
                };
                if row.status != DedicatedIpState::Created.as_str() {
                    return Ok(false);
                }
                row.status = DedicatedIpState::Attached.as_str().to_string();
                Ok(true)
            })
        }

        fn mark_rdns_ready(
            &self,
            id: Uuid,
            _hostname: String,
        ) -> BoxFuture<'_, Result<bool, IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(reason) = state.fail_mark_rdns_ready.clone() {
                    return Err(IpProviderError::Database(reason));
                }
                let Some(row) = state.rows.iter_mut().find(|r| r.id == id) else {
                    return Ok(false);
                };
                if row.status != DedicatedIpState::Attached.as_str() {
                    return Ok(false);
                }
                row.status = DedicatedIpState::RdnsReady.as_str().to_string();
                Ok(true)
            })
        }

        fn mark_warming(&self, id: Uuid) -> BoxFuture<'_, Result<bool, IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(reason) = state.fail_mark_warming.clone() {
                    return Err(IpProviderError::Database(reason));
                }
                let Some(row) = state.rows.iter_mut().find(|r| r.id == id) else {
                    return Ok(false);
                };
                if row.status != DedicatedIpState::RdnsReady.as_str() {
                    return Ok(false);
                }
                row.status = DedicatedIpState::Warming.as_str().to_string();
                row.warmup_started_at = Some(Utc::now());
                Ok(true)
            })
        }

        fn record_failure(
            &self,
            record: FailureRecord,
        ) -> BoxFuture<'_, Result<bool, IpProviderError>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(reason) = state.fail_record_failure.clone() {
                    return Err(IpProviderError::Database(reason));
                }
                if let Some(row) = state.rows.iter_mut().find(|r| r.id == record.id) {
                    if !matches!(
                        row.status.as_str(),
                        "provisioning" | "created" | "attached" | "rdns_ready"
                    ) {
                        return Ok(false);
                    }
                    row.status = record.status.as_str().to_string();
                    row.error_detail = Some(record.error_detail);
                    return Ok(true);
                }
                state.rows.push(FakeRow {
                    id: record.id,
                    status: record.status.as_str().to_string(),
                    warmup_started_at: None,
                    provider_resource_id: record.provider_resource_id,
                    error_detail: Some(record.error_detail),
                });
                Ok(true)
            })
        }
    }

    struct StubVerifier {
        result: RdnsVerification,
    }

    impl StubVerifier {
        fn verified() -> Self {
            Self {
                result: RdnsVerification::Verified {
                    ptr_names: vec!["mail.example.com.".to_string()],
                },
            }
        }

        fn mismatch() -> Self {
            Self {
                result: RdnsVerification::Mismatch {
                    ptr_names: vec!["other.example.net.".to_string()],
                    expected: "mail.example.com".to_string(),
                    reason: "PTR other.example.net. does not match expected mail.example.com"
                        .to_string(),
                },
            }
        }

        fn unavailable() -> Self {
            Self {
                result: RdnsVerification::LookupUnavailable {
                    reason: "resolver unavailable".to_string(),
                },
            }
        }
    }

    impl RdnsVerifier for StubVerifier {
        fn verify<'a>(
            &'a self,
            _ip_address: &'a str,
            _expected_hostname: &'a str,
        ) -> BoxFuture<'a, RdnsVerification> {
            Box::pin(async move { self.result.clone() })
        }
    }

    fn request() -> ProvisionRequest<'static> {
        ProvisionRequest {
            tenant_id: "tenant-1",
            region: None,
            default_location: "fsn1",
            mta_server_id: Some(42),
        }
    }

    // ── State machine tests ────────────────────────────────────

    #[test]
    fn test_state_machine_happy_path_advances_one_step() {
        assert_eq!(
            transition(DedicatedIpState::Provisioning, DedicatedIpState::Created).unwrap(),
            DedicatedIpState::Created
        );
        assert_eq!(
            transition(DedicatedIpState::Created, DedicatedIpState::Attached).unwrap(),
            DedicatedIpState::Attached
        );
        assert_eq!(
            transition(DedicatedIpState::Attached, DedicatedIpState::RdnsReady).unwrap(),
            DedicatedIpState::RdnsReady
        );
        assert_eq!(
            transition(DedicatedIpState::RdnsReady, DedicatedIpState::Warming).unwrap(),
            DedicatedIpState::Warming
        );
        assert_eq!(
            transition(DedicatedIpState::Warming, DedicatedIpState::Active).unwrap(),
            DedicatedIpState::Active
        );
        // Resume is idempotent, not a step.
        assert_eq!(
            transition(DedicatedIpState::Warming, DedicatedIpState::Warming).unwrap(),
            DedicatedIpState::Warming
        );
    }

    // Required adversarial #5: transitions cannot skip a step.
    #[test]
    fn test_transitions_cannot_skip_a_step() {
        let skips = [
            (DedicatedIpState::Created, DedicatedIpState::Warming),
            (DedicatedIpState::Provisioning, DedicatedIpState::Attached),
            (DedicatedIpState::Attached, DedicatedIpState::Active),
            (DedicatedIpState::RdnsReady, DedicatedIpState::Active),
            (DedicatedIpState::Created, DedicatedIpState::RdnsReady),
            (DedicatedIpState::Provisioning, DedicatedIpState::Warming),
            (DedicatedIpState::Provisioning, DedicatedIpState::Active),
        ];
        for (from, to) in skips {
            assert!(
                transition(from, to).is_err(),
                "{from:?} -> {to:?} must be refused (skipped step)"
            );
        }

        // Terminal states never resurrect; warming cannot fail backwards.
        assert!(transition(DedicatedIpState::Failed, DedicatedIpState::Warming).is_err());
        assert!(transition(DedicatedIpState::CleanupFailed, DedicatedIpState::Created).is_err());
        assert!(transition(DedicatedIpState::Retired, DedicatedIpState::Active).is_err());
        assert!(transition(DedicatedIpState::Warming, DedicatedIpState::Failed).is_err());
        assert!(transition(DedicatedIpState::Active, DedicatedIpState::Warming).is_err());

        // Failure edges from in-flight states are allowed.
        assert_eq!(
            transition(DedicatedIpState::Created, DedicatedIpState::Failed).unwrap(),
            DedicatedIpState::Failed
        );
        assert_eq!(
            transition(DedicatedIpState::Attached, DedicatedIpState::CleanupFailed).unwrap(),
            DedicatedIpState::CleanupFailed
        );
    }

    // Required adversarial #4: only warming/active are selectable.
    #[test]
    fn test_only_warming_and_active_are_selectable() {
        let anchor = Some(Utc::now());
        for state in DedicatedIpState::ALL {
            let expected = matches!(state, DedicatedIpState::Warming | DedicatedIpState::Active);
            assert_eq!(
                state.is_selectable(),
                expected,
                "unexpected selectability for {state:?}"
            );
            assert_eq!(
                state.is_selectable_with_anchor(anchor),
                expected,
                "unexpected anchored selectability for {state:?}"
            );
            assert_eq!(
                DedicatedIpState::parse_selectable(state.as_str(), anchor),
                expected,
                "raw status {} selectability mismatch",
                state.as_str()
            );
        }

        // Every non-selectable status must select nothing when read raw.
        for state in DedicatedIpState::ALL.iter().filter(|s| !s.is_selectable()) {
            assert!(
                !DedicatedIpState::parse_selectable(state.as_str(), anchor),
                "non-selectable {} must not be selectable",
                state.as_str()
            );
        }
    }

    /// Required adversarial #4, query-shaped: seed one row per status
    /// (including a state outside the vocabulary and a warming row without
    /// its anchor) and select with the production predicate — only genuinely
    /// warming/active rows come back.
    #[test]
    fn test_selection_over_all_statuses_returns_only_selectable_rows() {
        let store = FakeStore::new();
        let anchor = Some(Utc::now());
        {
            let mut state = store.state.lock().unwrap();
            for (i, status) in DedicatedIpState::ALL
                .iter()
                .map(|s| s.as_str())
                .chain(["not_a_status"])
                .enumerate()
            {
                state.rows.push(FakeRow {
                    id: Uuid::new_v4(),
                    status: status.to_string(),
                    // Keep every row anchored so only the status decides.
                    warmup_started_at: anchor,
                    provider_resource_id: Some(i as i64),
                    error_detail: None,
                });
            }
            // A warming row whose anchor is NULL must be excluded.
            state.rows.push(FakeRow {
                id: Uuid::new_v4(),
                status: "warming".to_string(),
                warmup_started_at: None,
                provider_resource_id: None,
                error_detail: None,
            });
        }

        let selected = store.selectable_rows();
        assert_eq!(
            selected.len(),
            2,
            "only warming (anchored) and active may be selected, got {selected:?}"
        );
        let mut statuses: Vec<&str> = selected.iter().map(|r| r.status.as_str()).collect();
        statuses.sort_unstable();
        assert_eq!(statuses, vec!["active", "warming"]);
    }

    // Required adversarial #7 (part): NULL warmup anchor on a warming row.
    #[test]
    fn test_warming_row_without_warmup_anchor_fails_closed() {
        assert!(!DedicatedIpState::Warming.is_selectable_with_anchor(None));
        assert!(!DedicatedIpState::parse_selectable("warming", None));
        assert!(DedicatedIpState::Warming.is_selectable_with_anchor(Some(Utc::now())));
        // `active` does not depend on the anchor.
        assert!(DedicatedIpState::Active.is_selectable_with_anchor(None));
    }

    // Required adversarial #7 (part): status outside the vocabulary.
    #[test]
    fn test_status_outside_vocabulary_fails_closed() {
        let anchor = Some(Utc::now());
        for hostile in [
            "",
            " ",
            "WARMING",
            "warming ",
            "bogus",
            "cleanup_failed_",
            "' OR 1=1 --",
            "active; DROP TABLE dedicated_ips",
        ] {
            assert!(
                DedicatedIpState::parse(hostile).is_none(),
                "{hostile:?} must not parse"
            );
            assert!(
                !DedicatedIpState::parse_selectable(hostile, anchor),
                "{hostile:?} must not be selectable"
            );
        }
        // In-vocabulary but non-selectable still selects nothing.
        assert!(!DedicatedIpState::parse_selectable("provisioning", anchor));
        assert!(!DedicatedIpState::parse_selectable("failed", anchor));
        assert!(!DedicatedIpState::parse_selectable(
            "cleanup_failed",
            anchor
        ));
        assert!(!DedicatedIpState::parse_selectable("pending", anchor));
    }

    // ── Orchestrator adversarial tests ─────────────────────────

    // Required adversarial #1: failed attach → cleanup, never selectable.
    #[test]
    fn test_attach_failure_cleans_up_and_never_warms() {
        let provider = FakeProvider::new();
        provider.state.lock().unwrap().fail_assign = Some("server refused".into());
        let store = FakeStore::new();
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(
            matches!(err, IpProviderError::AttachFailed(_)),
            "expected AttachFailed, got {err:?}"
        );
        assert_eq!(
            provider.delete_calls(),
            1,
            "failed attach must release the floating IP"
        );
        assert!(
            store.selectable_rows().is_empty(),
            "attach failure must never reach a selectable state"
        );
        let failed = store
            .rows()
            .into_iter()
            .find(|r| r.status == "failed")
            .expect("failure state must be recorded");
        assert!(
            failed
                .error_detail
                .as_deref()
                .unwrap_or_default()
                .contains("attach failed"),
            "provider response must be recorded: {:?}",
            failed.error_detail
        );
        assert!(
            !provider
                .calls()
                .iter()
                .any(|c| matches!(c, ProviderCall::SetRdns { .. })),
            "rDNS must not run after a failed attach"
        );
    }

    // Required adversarial #2: rDNS that does not resolve never warms.
    #[test]
    fn test_rdns_mismatch_cleans_up_and_never_warms() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        let verifier = StubVerifier::mismatch();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(
            matches!(err, IpProviderError::RdnsNotVerified { .. }),
            "expected RdnsNotVerified, got {err:?}"
        );
        assert_eq!(provider.delete_calls(), 1);
        assert!(store.selectable_rows().is_empty());
        let failed = store
            .rows()
            .into_iter()
            .find(|r| r.status == "failed")
            .expect("failure state must be recorded");
        assert!(failed
            .error_detail
            .as_deref()
            .unwrap_or_default()
            .contains("does not match"));
    }

    #[test]
    fn test_rdns_lookup_unavailable_is_not_success() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        let verifier = StubVerifier::unavailable();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(matches!(err, IpProviderError::RdnsNotVerified { .. }));
        assert_eq!(provider.delete_calls(), 1);
        assert!(store.selectable_rows().is_empty());
    }

    #[test]
    fn test_provisioning_without_verified_domain_never_creates_provider_resource() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        store.state.lock().unwrap().hostname = None;
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(matches!(err, IpProviderError::NoVerifiedDomain { .. }));
        assert_eq!(provider.create_calls(), 0, "must not spend provider money");
        assert!(store.selectable_rows().is_empty());
    }

    // Required adversarial #3: DB failure after provider create → delete.
    #[test]
    fn test_db_failure_after_provider_create_deletes_external_resource() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        store.state.lock().unwrap().fail_insert_created = Some("connection reset".into());
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(
            matches!(err, IpProviderError::Database(_)),
            "expected Database error, got {err:?}"
        );
        assert_eq!(
            provider.delete_calls(),
            1,
            "DB failure after provider creation must delete the floating IP"
        );
        assert!(store.selectable_rows().is_empty());
        let failed = store
            .rows()
            .into_iter()
            .find(|r| r.status == "failed")
            .expect("deleted-and-failed attempt must be recorded");
        assert!(failed
            .error_detail
            .as_deref()
            .unwrap_or_default()
            .contains("provider resource"));
        assert_eq!(
            failed.provider_resource_id,
            Some(1000),
            "the provider resource id must stay on the failure record for reconciliation"
        );
    }

    #[test]
    fn test_compensation_failure_is_recorded_as_cleanup_failed() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        store.state.lock().unwrap().fail_insert_created = Some("connection reset".into());
        provider.state.lock().unwrap().fail_delete = Some("provider 500".into());
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(
            matches!(err, IpProviderError::CompensationFailed { .. }),
            "expected CompensationFailed, got {err:?}"
        );
        let loud = store
            .rows()
            .into_iter()
            .find(|r| r.status == "cleanup_failed")
            .expect("cleanup failure must be recorded loudly");
        assert!(loud
            .error_detail
            .as_deref()
            .unwrap_or_default()
            .contains("PROVIDER CLEANUP FAILED"));
        assert!(store.selectable_rows().is_empty());
    }

    #[test]
    fn test_unrecordable_compensation_never_panics_and_never_selects() {
        let provider = FakeProvider::new();
        provider.state.lock().unwrap().fail_delete = Some("provider 500".into());
        let store = FakeStore::new();
        {
            let mut state = store.state.lock().unwrap();
            state.fail_insert_created = Some("db down".into());
            state.fail_record_failure = Some("db still down".into());
        }
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(matches!(err, IpProviderError::CompensationFailed { .. }));
        assert_eq!(provider.delete_calls(), 1);
        assert!(store.selectable_rows().is_empty());
        assert!(
            store.rows().is_empty(),
            "no failure row can be written when the DB is down"
        );
    }

    // Required adversarial #6: concurrent attempts never leave two
    // promotable rows from a losing attempt.
    #[test]
    fn test_concurrent_attempts_compensate_the_loser() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        store.state.lock().unwrap().fail_insert_created_after = Some(1);
        let verifier = StubVerifier::verified();

        let req = request();
        let (first, second) = futures::executor::block_on(async {
            futures::join!(
                run_provisioning(&provider, &store, &verifier, &req),
                run_provisioning(&provider, &store, &verifier, &req)
            )
        });

        assert!(first.is_ok(), "first attempt must succeed: {first:?}");
        assert!(
            matches!(second, Err(IpProviderError::Database(_))),
            "losing attempt must fail closed: {second:?}"
        );
        assert_eq!(
            provider.create_calls(),
            2,
            "each attempt owns a distinct provider resource (batch semantics)"
        );
        assert_eq!(
            provider.delete_calls(),
            1,
            "the losing attempt must delete its own provider resource"
        );
        assert_eq!(
            store.selectable_rows().len(),
            1,
            "exactly one attempt may become selectable"
        );
    }

    // Required adversarial #7 (part): empty provider IP fails closed.
    #[test]
    fn test_empty_provider_ip_fails_closed() {
        let provider = FakeProvider::new();
        provider.state.lock().unwrap().resource_ip = "   ".to_string();
        let store = FakeStore::new();
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(matches!(err, IpProviderError::EmptyProviderIp));
        assert_eq!(provider.delete_calls(), 1);
        assert!(store.selectable_rows().is_empty());
    }

    // Required adversarial #7 (part): a provider that throws on every call.
    #[test]
    fn test_provider_throwing_on_every_call_fails_closed() {
        let provider = FakeProvider::new();
        provider.state.lock().unwrap().fail_all = true;
        let store = FakeStore::new();
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(matches!(err, IpProviderError::HetznerApi(_)));
        assert!(store.rows().is_empty(), "no row may exist");
        assert!(store.selectable_rows().is_empty());
    }

    #[test]
    fn test_attach_without_configured_server_fails_closed_and_releases() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        let verifier = StubVerifier::verified();
        let mut req = request();
        req.mta_server_id = None;

        let err = futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &req))
            .unwrap_err();

        assert!(matches!(err, IpProviderError::AttachTargetUnavailable));
        assert_eq!(provider.delete_calls(), 1);
        assert!(store.selectable_rows().is_empty());
    }

    #[test]
    fn test_tampered_state_transition_is_refused_and_releases() {
        let provider = FakeProvider::new();
        let store = FakeStore::new();
        // Simulate a racing writer that moved the row out from under us.
        store.state.lock().unwrap().mark_attached_refuses = true;
        let verifier = StubVerifier::verified();

        let err =
            futures::executor::block_on(run_provisioning(&provider, &store, &verifier, &request()))
                .unwrap_err();

        assert!(matches!(
            err,
            IpProviderError::InvalidStateTransition { .. }
        ));
        assert_eq!(provider.delete_calls(), 1);
        assert!(store.selectable_rows().is_empty());
    }

    // ── Warmup schedule tests (unchanged) ──────────────────────

    use super::warmup_schedule::*;

    #[test]
    fn test_warmup_schedule() {
        assert_eq!(limit_for_day(0), 50);
        assert_eq!(limit_for_day(5), 250);
        assert_eq!(limit_for_day(15), 5_000);
        assert_eq!(limit_for_day(45), 75_000);
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS), u64::MAX);
    }

    // ── Aggressive fail-first: warmup schedule ─────────────────

    #[test]
    fn test_warmup_day_0_is_minimum() {
        assert_eq!(limit_for_day(0), 50, "Day 0 must start at 50 emails");
    }

    #[test]
    fn test_warmup_day_1_same_as_day_0() {
        assert_eq!(
            limit_for_day(0),
            limit_for_day(1),
            "Days 0-1 should have the same limit"
        );
    }

    #[test]
    fn test_warmup_monotonically_increasing() {
        let mut prev = 0u64;
        for day in 0..=FULL_WARMUP_DAYS + 1 {
            let limit = limit_for_day(day);
            assert!(limit >= prev,
                "warmup must be monotonically non-decreasing: day {day} limit {limit} < prev {prev}");
            prev = limit;
        }
    }

    #[test]
    fn test_warmup_day_44_is_not_unlimited() {
        // Day 44 must still be capped before the extended ramp tiers start.
        assert!(
            limit_for_day(44) < u64::MAX,
            "Day 44 must not be unlimited — IP is still warming"
        );
        assert_eq!(limit_for_day(44), 50_000);
    }

    #[test]
    fn test_warmup_day_45_starts_extended_ramp() {
        assert_eq!(limit_for_day(45), 75_000);
    }

    #[test]
    fn test_warmup_last_day_before_graduation_is_still_capped() {
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS - 1), 250_000);
        assert!(limit_for_day(FULL_WARMUP_DAYS - 1) < u64::MAX);
    }

    #[test]
    fn test_warmup_graduation_day_is_unlimited() {
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS), u64::MAX);
    }

    #[test]
    fn test_warmup_full_period_is_60_days() {
        assert_eq!(
            FULL_WARMUP_DAYS, 60,
            "FULL_WARMUP_DAYS must match the warmup schedule graduation day"
        );
    }

    #[test]
    fn test_warmup_no_gaps_in_coverage() {
        // Every day across the full schedule must have a defined limit.
        for day in 0..=FULL_WARMUP_DAYS + 5 {
            let limit = limit_for_day(day);
            assert!(limit > 0, "Day {day} must have a positive limit");
        }
    }

    #[test]
    fn test_warmup_boundary_days() {
        // Test exact boundary values
        assert_eq!(limit_for_day(2), 100); // day 2-3
        assert_eq!(limit_for_day(4), 250); // day 4-5
        assert_eq!(limit_for_day(6), 500); // day 6-7
        assert_eq!(limit_for_day(8), 1_000); // day 8-10
        assert_eq!(limit_for_day(11), 2_500); // day 11-14
        assert_eq!(limit_for_day(15), 5_000); // day 15-20
        assert_eq!(limit_for_day(21), 10_000); // day 21-28
        assert_eq!(limit_for_day(29), 25_000); // day 29-35
        assert_eq!(limit_for_day(36), 50_000); // day 36-44
        assert_eq!(limit_for_day(45), 75_000); // day 45-49
        assert_eq!(limit_for_day(50), 100_000); // day 50-54
        assert_eq!(limit_for_day(55), 250_000); // day 55-59
        assert_eq!(limit_for_day(FULL_WARMUP_DAYS), u64::MAX); // graduation day
    }

    #[test]
    fn test_allocating_ip_add_on_price_consistency() {
        // The price constant in ip_provider must match dedicated_ips route
        assert_eq!(
            super::ADD_ON_PRICE_CENTS,
            3000,
            "add-on price must be $30.00 = 3000 cents across all modules"
        );
    }

    #[test]
    fn test_non_occupying_statuses_match_the_state_machine() {
        for status in NON_OCCUPYING_STATUSES {
            let state = DedicatedIpState::parse(status)
                .unwrap_or_else(|| panic!("{status} must be in the vocabulary"));
            assert!(
                !state.is_selectable(),
                "{status} must never be selectable for sending"
            );
        }
        assert!(
            !NON_OCCUPYING_STATUSES.contains(&"warming"),
            "warming occupies the allowance and must be counted"
        );
        assert!(
            !NON_OCCUPYING_STATUSES.contains(&"active"),
            "active occupies the allowance and must be counted"
        );
    }
}
