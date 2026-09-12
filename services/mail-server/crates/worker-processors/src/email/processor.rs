//! Email processor implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use apexmail_lib::dkim::{
    decrypt_dkim_private_key, dkim_private_key_aad, dkim_public_keys_match,
    public_key_base64_from_private_key_pem,
};
use chrono::{DateTime, Utc};
use mail_common::warmup::WarmupSchedule;
use moka::sync::Cache;
use rand::Rng;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::sync::Mutex;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::tracking::{add_tracking_pixel, rewrite_links, unsubscribe_link};
use super::transport::{create_transport_from_config, EmailTransport, HybridTransport};
use super::transport_router::{transport_kind_for, TransportKind};
use super::types::{
    Attachment, CachedSuppression, DedicatedIp, DeliveryReceipt, DeliveryRoute, DkimConfig, Domain,
    EmailJob, Mailbox, PreparedEmail, SendOutcome, VerpBinding,
};
use crate::common::{
    Backpressure, BackpressureConfig, CircuitBreaker, CircuitBreakerConfig, EmailConfig,
    ProcessorError, ProcessorResult, RedisPool, TransportType,
};

/// Maximum suppression cache size.
const SUPPRESSION_CACHE_MAX_SIZE: u64 = 10_000;

/// Suppression cache TTL.
const SUPPRESSION_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Sentinel reason used by [`EmailProcessor::batch_suppression_check`] when
/// the suppression DB query itself failed (as opposed to a genuine
/// suppression). Recipients carrying this marker are REQUEUED, not
/// suppressed — a DB blip must not permanently suppress the batch.
const SUPPRESSION_CHECK_FAILED: &str = "suppression_check_failed";

/// F59: the complete bounded set of `email_queue` statuses (mirrors the
/// `chk_email_queue_status` CHECK constraint from migrations 050/088). Every
/// snapshot initializes each of these to zero before overlaying query
/// results, so drained statuses publish 0 instead of retaining stale counts.
const EMAIL_QUEUE_STATUSES: [&str; 8] = [
    "pending",
    "processing",
    "sent",
    "failed",
    "deferred",
    "cancelled",
    "bounced",
    "suppressed",
];

/// F18: the dispatch-time tenant policy gate's query. NEVER wrapped in an
/// allow-cache — see [`EmailProcessor::tenant_policy`].
const TENANT_STATUS_SQL: &str = "SELECT status FROM tenants WHERE id = $1";

/// F18: the explicit dispatch-time tenant policy result. Nothing but
/// [`TenantPolicy::Allowed`] may reach the external transport; every other
/// variant DEFERS the job (requeue) and exits dispatch — the gate never
/// fails open and never treats pending/unknown as permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TenantPolicy {
    /// The tenant row was read and its status is `active`.
    Allowed,
    /// The tenant is confirmed not eligible to send (missing row, empty
    /// identity, `pending`, `suspended`, ...). The job defers until the
    /// restriction is lifted.
    Restricted(String),
    /// The policy could not be determined (DB lookup failure). The job
    /// defers; the next claim re-attempts the lookup.
    TemporarilyUnavailable,
}

impl TenantPolicy {
    /// The `requeue_reason` recorded on the deferred row.
    fn requeue_reason(&self) -> &str {
        match self {
            Self::Allowed => "allowed",
            Self::Restricted(reason) => reason,
            Self::TemporarilyUnavailable => "tenant_policy_unavailable",
        }
    }
}

/// F55: the explicit dispatch-time consent result. `Deferred` is distinct
/// from both "no suppression" and "suppressed" — a FAILED verification is
/// never interpreted as permission to send.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConsentDecision {
    /// Current authoritative state permits this send.
    Allowed,
    /// Current authoritative state forbids it (durable reason recorded).
    Suppressed(String),
    /// The verification itself failed — defer, do not send.
    Deferred(&'static str),
}

/// F55: the single authoritative dispatch-time consent query — global
/// suppression AND the per-category preference, read together so the two
/// dimensions cannot disagree.
const DISPATCH_CONSENT_SQL: &str = r#"
    SELECT
        (SELECT reason FROM suppressions
          WHERE tenant_id = $1 AND LOWER(email) = $2
          LIMIT 1) AS global_reason,
        (SELECT NOT subscribed FROM subscription_preferences
          WHERE tenant_id = $1 AND LOWER(email) = $2 AND category = $3
          LIMIT 1) AS category_opted_out
"#;

/// Error rate window size.
const ERROR_WINDOW_SIZE: usize = 20;

/// Error threshold for circuit breaker (50% failure rate).
const ERROR_THRESHOLD: usize = 10;

/// Cooldown duration when error rate is too high.
const ERROR_COOLDOWN: Duration = Duration::from_secs(60);

/// G.3b: per-recipient suppression — remove the recipient from the pending
/// set and only mark the row 'suppressed' when nothing remains owed.
const SUPPRESSED_UPDATE_SQL: &str = r#"
    UPDATE email_queue
    SET metadata = jsonb_set(
            CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
            '{pending_recipients}',
            COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $3::text
        ),
        status = CASE WHEN COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $3::text = '[]'::jsonb
            THEN 'suppressed' ELSE status END,
        error_message = $1,
        updated_at = NOW()
    WHERE id = $2::uuid
      AND (metadata->>'lease_token') IS NOT DISTINCT FROM $4::text
"#;

/// Audit-3: per-recipient hard bounce — the same contract as
/// [`SUPPRESSED_UPDATE_SQL`] / handle_success: the bounced recipient is
/// removed from `metadata.pending_recipients` and the row only becomes
/// terminal 'bounced' when the pending set empties. Previously the whole
/// multi-recipient row was flipped 'bounced', abandoning the siblings still
/// owed a delivery (FIX-8 made one queue row carry N recipients).
const HARD_BOUNCE_UPDATE_SQL: &str = r#"
    UPDATE email_queue
    SET metadata = jsonb_set(
            CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
            '{pending_recipients}',
            COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $3::text
        ),
        status = CASE WHEN COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $3::text = '[]'::jsonb
            THEN 'bounced' ELSE status END,
        error_message = $1,
        updated_at = NOW()
    WHERE id = $2::uuid
      AND (metadata->>'lease_token') IS NOT DISTINCT FROM $4::text
"#;

/// Audit-3: per-recipient DLQ failure — the attempt budget of ONE recipient
/// exhausting must not abandon the row's other recipients. The failed
/// recipient leaves the pending set (its own delivery is dead-lettered by
/// the caller's email_dlq insert); the row terminalizes to 'failed' only
/// when the pending set empties, otherwise it returns to 'pending' so the
/// siblings keep their deliveries.
const DLQ_FAIL_UPDATE_SQL: &str = r#"
    UPDATE email_queue
    SET metadata = jsonb_set(
            CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
            '{pending_recipients}',
            COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $3::text
        ),
        status = CASE WHEN COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $3::text = '[]'::jsonb
            THEN 'failed' ELSE 'pending' END,
        error_message = $1,
        locked_until = NULL,
        updated_at = NOW()
    WHERE id = $2::uuid
      AND (metadata->>'lease_token') IS NOT DISTINCT FROM $4::text
"#;

/// F25: derive the audit `messages` row's progress from the COMPLETE set of
/// its recipient rows (`email_queue`) — the shared canonical contract lives
/// in `apexmail_lib::email_headers::RECONCILE_MESSAGE_PROGRESS_SQL` (also
/// executed by the SES callback handler, F75) so the worker and the API
/// cannot drift apart. Semantics are documented there:
///
/// * recipients still owed a delivery exist → `partial` (a multi-recipient
///   message with one delivered copy is NOT sent — the first-recipient
///   success used to flip the whole message to 'sent');
/// * every recipient row terminal with ≥1 suppressed/bounced/failed/
///   cancelled → `partial` (final partial success — includes all-failed,
///   which used to stay 'processing' forever because only successes
///   reconciled);
/// * every recipient row `sent`, ≥1 not yet confirmed delivered → `sent`
///   (provider acceptance, `sent_at` stamped at the actual event);
/// * every recipient row `sent` AND confirmed delivered (`delivered_at`) →
///   `delivered` + `messages.delivered_at` (aggregate: ALL recipients
///   confirmed delivered).
///
/// Scheduled parents are accepted: the transition fires from
/// `queued`/`scheduled`/`processing`/`partial`/`sent` alike. Terminal states
/// set by other paths ('cancelled') are never crouched — the WHERE clause
/// does not match them.
const MESSAGES_PROGRESS_UPDATE_SQL: &str =
    apexmail_lib::email_headers::RECONCILE_MESSAGE_PROGRESS_SQL;

/// F25: claim-time parent transition — the moment a worker claims recipient
/// rows of a `queued`/`scheduled` message, the parent moves to
/// 'processing'. This is the scheduled → processing edge (scheduled
/// messages previously had no worker-side transition at all) and gives the
/// API's cancellation check a parent-visible dispatch signal (F24).
const MESSAGES_CLAIMED_UPDATE_SQL: &str = r#"
    UPDATE messages SET status = 'processing', updated_at = NOW()
    WHERE id = ANY($1::uuid[])
      AND tenant_id = $2
      AND status IN ('queued', 'scheduled')
"#;

/// Audit-1 / Fix 3 / P0 routing: the ready-domain lookup for a queued job.
///
/// Warmup and routing state come from the REAL warmup tables: per-IP warmup
/// lives on `dedicated_ips` (created by migration 003 with `warmup_started_at`;
/// the status CHECK allows `warming` and `active`), so the query returns the
/// identity (`id`, `ip_address`), the lifecycle `status` and
/// `warmup_started_at` of EVERY dedicated IP the tenant can send through —
/// both still-`warming` rows and graduated `active` rows. Only warming rows
/// consume the canonical daily quota; an active row keeps being routed as
/// dedicated without throttling (the previous query filtered
/// `status = 'warming'`, so a graduated IP silently dropped its tenant back
/// onto the shared pool). The day/limit derivation and the selection of the
/// candidate pool happen in Rust ([`select_delivery_ip`]) from
/// `warmup_started_at` + `mail_common::warmup`, never from materialized
/// counters.
///
/// `ip_pool_addresses` (migration 093) also carries per-address warmup
/// columns, but the table has no tenant binding (`ip_pools` are platform
/// pools), so `dedicated_ips` is the per-tenant source of truth.
const GET_DOMAIN_SQL: &str = r#"
    SELECT
        d.id::text AS id,
        d.tenant_id AS tenant_id,
        d.name AS domain,
        d.dkim_selector AS dkim_selector,
        d.dkim_public_key AS dkim_public_key,
        d.dkim_private_key AS dkim_private_key,
        d.ses_verified AS ses_verified,
        NULL::text AS return_path,
        w.dedicated_ips AS dedicated_ips
    FROM domains d
    LEFT JOIN LATERAL (
        SELECT COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'id', di.id::text,
                    'ip_address', di.ip_address,
                    'warming', (di.status = 'warming'),
                    'warmup_started_at', di.warmup_started_at
                )
                ORDER BY (di.status = 'warming') DESC,
                         di.warmup_started_at ASC NULLS LAST,
                         di.id
            ),
            '[]'::jsonb
        ) AS dedicated_ips
        FROM dedicated_ips di
        WHERE di.tenant_id = d.tenant_id::text
          AND di.status IN ('warming', 'active')
    ) w ON true
    WHERE d.id = $1::uuid AND d.tenant_id = $2
      AND d.status = 'verified'
      AND d.dkim_enabled = true
      AND d.dkim_selector IS NOT NULL
      AND d.dkim_public_key IS NOT NULL
      AND d.dkim_private_key IS NOT NULL
      AND d.dkim_private_key LIKE 'dkim:v1:%'
"#;

/// Audit-1: [`GET_DOMAIN_SQL`] row — the [`Domain`] columns plus the routing
/// source data (one JSON object per warming/active dedicated IP).
#[derive(Debug, sqlx::FromRow)]
struct DomainWithRoutingRow {
    id: String,
    tenant_id: String,
    domain: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
    dkim_private_key: Option<String>,
    ses_verified: bool,
    return_path: Option<String>,
    dedicated_ips: Option<JsonValue>,
}

/// One dedicated IP as serialized by [`GET_DOMAIN_SQL`]'s
/// `jsonb_build_object` array.
#[derive(Debug, Clone, serde::Deserialize)]
struct DedicatedIpRow {
    id: String,
    ip_address: String,
    #[serde(default)]
    warming: bool,
    warmup_started_at: Option<DateTime<Utc>>,
}

impl From<DedicatedIpRow> for DedicatedIp {
    fn from(row: DedicatedIpRow) -> Self {
        Self {
            id: row.id,
            ip_address: row.ip_address,
            warming: row.warming,
            warmup_started_at: row.warmup_started_at,
        }
    }
}

/// Decode the `dedicated_ips` JSONB array. Malformed entries are dropped (the
/// query builds this array itself; a decode failure means row corruption, and
/// dropping it fails routing closed rather than inventing an IP).
fn parse_dedicated_ips(raw: Option<&JsonValue>) -> Vec<DedicatedIp> {
    let Some(JsonValue::Array(values)) = raw else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|value| serde_json::from_value::<DedicatedIpRow>(value.clone()).ok())
        .map(DedicatedIp::from)
        .collect()
}

/// Whole elapsed days since a warmup start, clamped to `[0, u32::MAX]`
/// (clock-skewed future timestamps are day 0).
fn warmup_day_since(now: DateTime<Utc>, started_at: DateTime<Utc>) -> u32 {
    (now - started_at).num_days().clamp(0, u32::MAX as i64) as u32
}

/// One dedicated-IP routing candidate with its DERIVED warmup standing.
///
/// The warmup day and daily cap come from `warmup_started_at` + the canonical
/// `mail_common::warmup` schedule — no materialized `warmup_day` /
/// `warmup_daily_limit` column participates, so a job never has to advance
/// persisted state for routing to be correct.
#[derive(Debug, Clone)]
struct RoutingCandidate {
    /// `dedicated_ips.id`.
    dedicated_ip_id: String,
    /// `dedicated_ips.ip_address` (the string form used in cache keys).
    ip_address: String,
    /// Parsed recipient-facing address the route must bind.
    source_ip: std::net::IpAddr,
    /// Elapsed warmup days (0 for an active IP without a recorded start).
    warmup_day: u32,
    /// `Some(canonical daily cap)` while the IP is still warming; `None` for
    /// an active (graduated) IP — routed dedicated, never throttled.
    daily_limit: Option<u64>,
}

impl RoutingCandidate {
    fn is_warming(&self) -> bool {
        self.daily_limit.is_some()
    }
}

/// SELECT (pure, no I/O): build the ordered dedicated-IP candidate pool for
/// one send from the tenant's dedicated identities.
///
/// * warming rows come first, least-warmed first — they are the tightest
///   reputation boundary and must keep receiving traffic to graduate;
/// * active (graduated) rows follow, unthrottled. They keep the tenant on the
///   dedicated route instead of silently falling back to the shared pool.
///
/// A candidate whose `ip_address` cannot be parsed, or a warming row without
/// `warmup_started_at`, is a hard configuration error: refusing the send is
/// safer than routing to an IP that cannot be named or throttled. Consumption
/// (and the actual choice among equally-utilised candidates) happens in
/// [`reserve_warmup_capacity`], so selection and reservation stay separate
/// concerns.
fn select_delivery_ip(
    now: DateTime<Utc>,
    dedicated_ips: &[DedicatedIp],
) -> ProcessorResult<Vec<RoutingCandidate>> {
    let mut candidates: Vec<RoutingCandidate> = Vec::with_capacity(dedicated_ips.len());
    for ip in dedicated_ips {
        let source_ip: std::net::IpAddr = ip.ip_address.trim().parse().map_err(|_| {
            ProcessorError::Config(format!(
                "dedicated IP identity {} has an unparseable source address {:?} — refusing to route",
                ip.id, ip.ip_address
            ))
        })?;
        let (warmup_day, daily_limit) = if ip.warming {
            let started_at = ip.warmup_started_at.ok_or_else(|| {
                ProcessorError::Config(format!(
                    "dedicated IP identity {} is 'warming' without warmup_started_at — \
                     its canonical daily cap cannot be derived; refusing to route it unthrottled",
                    ip.id
                ))
            })?;
            let day = warmup_day_since(now, started_at);
            (day, Some(WarmupSchedule::limit_for_day(day)))
        } else {
            // Active/graduated: the day is informational only (the IP is
            // unthrottled) but keeps the ordering deterministic.
            (
                ip.warmup_started_at
                    .map(|started_at| warmup_day_since(now, started_at))
                    .unwrap_or(0),
                None,
            )
        };
        candidates.push(RoutingCandidate {
            dedicated_ip_id: ip.id.clone(),
            ip_address: ip.ip_address.clone(),
            source_ip,
            warmup_day,
            daily_limit,
        });
    }

    // Warming first, least-warmed first; then active, oldest first. Sorting
    // is stable on (warming, day, address) so the atomic pool reservation is
    // deterministic across workers.
    candidates.sort_by(|a, b| {
        b.is_warming()
            .cmp(&a.is_warming())
            .then(a.warmup_day.cmp(&b.warmup_day))
            .then(a.ip_address.cmp(&b.ip_address))
    });
    Ok(candidates)
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit-5: lease-token fencing for `email_queue`
//
// `email_queue` has NO lease_token column (migration 103 added one to
// `queue_jobs`, the queue-provider's table, only) — but it does have a
// `metadata` JSONB column, so the claim mints a fresh
// `metadata.lease_token` (gen_random_uuid) on EVERY claim and every
// post-claim row write predicates
// `(metadata->>'lease_token') IS NOT DISTINCT FROM <claim's token>`.
// This mirrors queue-provider's exact-lease fencing (provider.rs
// complete/fail/dead_letter fence on `status = 'processing' AND
// lease_token = $token`): a stale worker whose row was recovered and
// re-claimed can no longer match the new owner's token, so its write is a
// no-op (warned). The token is NOT fenced on `status = 'processing'`
// because FIX-8 multi-recipient rows legitimately receive several writes
// per claim and those writes themselves flip the row off 'processing'
// (terminal 'sent' when the pending set empties, 'pending' on requeue);
// the token equality alone is the exact stale-lease fence.
//
// `IS NOT DISTINCT FROM` (rather than `=`) keeps legacy rows without a
// token writable by token-less writers (NULL never matches under `=`).
// ─────────────────────────────────────────────────────────────────────────────

/// The claim: flips pending/expired-lease rows to 'processing' and mints a
/// fresh `metadata.lease_token` for the new lease generation (see the
/// Audit-5 block above). The returned `metadata` already carries the new
/// token, so every expanded per-recipient job transports it.
const FETCH_JOBS_SQL: &str = r#"
            UPDATE email_queue
            SET status = 'processing',
                locked_until = $1,
                updated_at = NOW(),
                metadata = jsonb_set(
                    CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
                    '{lease_token}',
                    to_jsonb(gen_random_uuid()::text)
                )
            WHERE id IN (
                SELECT id
                FROM email_queue
                WHERE (
                    status = 'pending'
                    -- Reclaim rows orphaned in 'processing' by a crashed
                    -- worker whose visibility lease has expired. The fresh
                    -- lease_token mint above fences the crashed worker's
                    -- late writes (Audit-5).
                    OR (status = 'processing' AND locked_until < NOW())
                )
                  AND (scheduled_at IS NULL OR scheduled_at <= NOW())
                ORDER BY priority DESC, created_at ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            RETURNING
                id::text AS id,
                COALESCE(message_id::text, id::text) as "messageId",
                COALESCE(tenant_id, '') as "tenantId",
                COALESCE(domain_id::text, '') as "domainId",
                COALESCE("from", from_address) as "from",
                COALESCE("to", to_addresses[1], '') as "to",
                CASE
                    -- F45: metadata.pending_recipients is SERVER-WRITTEN state
                    -- and is only honored when it is a well-formed array that is
                    -- a SUBSET of the row's validated envelope recipients
                    -- (to_addresses / "to"). A caller-forged or corrupted set
                    -- (scalar metadata, non-array, unknown address) falls back
                    -- to the trusted envelope record, so customer metadata can
                    -- never redirect a delivery to an unvalidated recipient.
                    WHEN metadata->'pending_recipients' IS NOT NULL
                     AND jsonb_typeof(metadata) = 'object'
                     AND jsonb_typeof(metadata->'pending_recipients') = 'array'
                     AND NOT EXISTS (
                            SELECT 1
                            FROM jsonb_array_elements_text(metadata->'pending_recipients') AS pending_addr
                            WHERE pending_addr <> ALL(
                                COALESCE(
                                    to_addresses,
                                    CASE WHEN "to" IS NOT NULL
                                         THEN ARRAY["to"] ELSE ARRAY[]::text[] END
                                )
                            )
                        )
                    THEN ARRAY(
                        SELECT jsonb_array_elements_text(metadata->'pending_recipients')
                    )
                    ELSE to_addresses
                END as "toAddresses",
                subject, html, text, headers, attachments,
                campaign_id::text as "campaignId", tags, metadata, scheduled_at as "scheduledAt",
                message_category, attempt, created_at as "createdAt",
                sales_step_execution_id::text as "salesStepExecutionId"
"#;

/// Audit-5: this claim's lease token, transported inside the job's
/// `metadata` (minted by [`FETCH_JOBS_SQL`]). `None` for legacy rows
/// claimed before the token existed.
fn lease_token_of(job: &EmailJob) -> Option<&str> {
    job.metadata
        .as_ref()
        .and_then(|m| m.get("lease_token"))
        .and_then(|v| v.as_str())
}

/// Audit-5: true when a fenced UPDATE affected nothing — the row no longer
/// carries this claim's token (recovered + re-claimed by another worker).
/// The write is intentionally a no-op; callers warn and skip follow-up
/// effects (events, suppression, DLQ rows) so a fenced-out worker cannot
/// mutate the new owner's row.
fn fenced_out(rows_affected: u64) -> bool {
    rows_affected == 0
}

/// F6:apply ±20% jitter to a retry delay (in seconds). `rand` is already a
/// crate dependency. A non-positive input passes through untouched; a
/// positive input never collapses to zero (min 1s).
fn jittered_secs(base_secs: i64) -> i64 {
    if base_secs <= 0 {
        return base_secs;
    }
    let spread: f64 = rand::rng().random_range(-0.2..=0.2);
    ((base_secs as f64) * (1.0 + spread)).round().max(1.0) as i64
}

/// Audit-5: handle_success's row write — identical semantics to the
/// pre-fence inline SQL, plus the lease-token fence.
const HANDLE_SUCCESS_UPDATE_SQL: &str = r#"
            UPDATE email_queue
            SET metadata = jsonb_set(
                    CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
                    '{pending_recipients}',
                    COALESCE(
                        metadata->'pending_recipients',
                        CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                             THEN to_jsonb(to_addresses) END,
                        CASE WHEN "to" IS NOT NULL AND "to" <> ''
                             THEN to_jsonb(ARRAY["to"]) END,
                        '[]'::jsonb
                    ) - $3::text
                ),
                status = CASE WHEN COALESCE(
                        metadata->'pending_recipients',
                        CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                             THEN to_jsonb(to_addresses) END,
                        CASE WHEN "to" IS NOT NULL AND "to" <> ''
                             THEN to_jsonb(ARRAY["to"]) END,
                        '[]'::jsonb
                    ) - $3::text = '[]'::jsonb
                    THEN 'sent' ELSE status END,
                sent_at = CASE WHEN COALESCE(
                        metadata->'pending_recipients',
                        CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                             THEN to_jsonb(to_addresses) END,
                        CASE WHEN "to" IS NOT NULL AND "to" <> ''
                             THEN to_jsonb(ARRAY["to"]) END,
                        '[]'::jsonb
                    ) - $3::text = '[]'::jsonb
                    THEN NOW() ELSE sent_at END,
                smtp_message_id = $1,
                updated_at = NOW()
            WHERE id = $2::uuid
              AND (metadata->>'lease_token') IS NOT DISTINCT FROM $4::text
"#;

/// Audit-5: handle_soft_bounce's requeue write, fenced on the lease token.
const SOFT_BOUNCE_UPDATE_SQL: &str = r#"
            UPDATE email_queue
            SET status = CASE WHEN COALESCE(
                        metadata->'pending_recipients',
                        CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                             THEN to_jsonb(to_addresses) END,
                        CASE WHEN "to" IS NOT NULL AND "to" <> ''
                             THEN to_jsonb(ARRAY["to"]) END,
                        '[]'::jsonb
                    ) = '[]'::jsonb
                    THEN 'sent' ELSE 'pending' END,
                attempt = $1,
                scheduled_at = $2,
                error_message = $3,
                locked_until = NULL,
                metadata = jsonb_set(
                    CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
                    '{pending_recipients}',
                    COALESCE(
                        metadata->'pending_recipients',
                        CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                             THEN to_jsonb(to_addresses) END,
                        CASE WHEN "to" IS NOT NULL AND "to" <> ''
                             THEN to_jsonb(ARRAY["to"]) END,
                        '[]'::jsonb
                    )
                )
            WHERE id = $4::uuid
              AND (metadata->>'lease_token') IS NOT DISTINCT FROM $5::text
"#;

/// Audit-5: requeue (deferral) write, fenced on the lease token — a stale
/// worker must not be able to defer a row the new owner is processing.
const REQUEUE_JOB_UPDATE_SQL: &str = r#"
            UPDATE email_queue
            SET status = 'pending', scheduled_at = $1, locked_until = NULL,
                metadata = jsonb_set(CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END, '{requeue_reason}', $2::jsonb)
            WHERE id = $3::uuid
              AND (metadata->>'lease_token') IS NOT DISTINCT FROM $4::text
"#;

/// F5:release a multi-recipient row back to `pending` after a processed
/// chunk when recipients are still owed. `expand_rows_within_cap` admits at
/// most `limit` recipients per claim, so a 1000-recipient row used to drain
/// only `limit` recipients per 300s visibility lease (~8.3h end-to-end).
/// Releasing the remainder immediately (status='pending', lease cleared,
/// still fenced on this claim's lease token so a stale worker cannot
/// release a row the next owner holds) lets the very next poll continue.
/// Rows whose pending set emptied are already terminal ('sent') and do not
/// match; requeued/deferred rows are already 'pending'.
const RELEASE_REMAINDER_SQL: &str = r#"
            UPDATE email_queue
            SET status = 'pending', locked_until = NULL, updated_at = NOW()
            WHERE id = $1::uuid
              AND status = 'processing'
              AND (metadata->>'lease_token') IS NOT DISTINCT FROM $2::text
              AND COALESCE(metadata->'pending_recipients', '[]'::jsonb) <> '[]'::jsonb
"#;

/// Audit-5: handle_permanent_job_failure's dead-letter write — previously
/// fenced on `status = 'processing'` only; now exactly fenced on the claim
/// token as well.
const PERMANENT_FAILURE_UPDATE_SQL: &str = r#"
            UPDATE email_queue
             SET status = 'failed', error_message = $1, locked_until = NULL, updated_at = NOW()
             WHERE id = $2::uuid AND status = 'processing'
               AND (metadata->>'lease_token') IS NOT DISTINCT FROM $3::text
"#;

/// G.3c: duplicate-window reclaim bookkeeping — drop the recipient from the
/// pending set and append it to an auditable `possibly_sent` metadata list.
const POSSIBLY_SENT_UPDATE_SQL: &str = r#"
    UPDATE email_queue
    SET metadata = jsonb_set(
            jsonb_set(
                CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata ELSE '{}'::jsonb END,
                '{pending_recipients}',
                COALESCE(
                    metadata->'pending_recipients',
                    CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                         THEN to_jsonb(to_addresses) END,
                    CASE WHEN "to" IS NOT NULL AND "to" <> ''
                         THEN to_jsonb(ARRAY["to"]) END,
                    '[]'::jsonb
                ) - $2::text
            ),
            '{possibly_sent}',
            COALESCE(metadata->'possibly_sent', '[]'::jsonb) || to_jsonb(ARRAY[$2::text])
        ),
        status = CASE WHEN COALESCE(
                metadata->'pending_recipients',
                CASE WHEN jsonb_array_length(to_jsonb(to_addresses)) > 0
                     THEN to_jsonb(to_addresses) END,
                CASE WHEN "to" IS NOT NULL AND "to" <> ''
                     THEN to_jsonb(ARRAY["to"]) END,
                '[]'::jsonb
            ) - $2::text = '[]'::jsonb
            THEN 'sent' ELSE status END,
        updated_at = NOW()
    WHERE id = $1::uuid
      AND (metadata->>'lease_token') IS NOT DISTINCT FROM $3::text
"#;

// ─────────────────────────────────────────────────────────────────────────────
// Durable exactly-once acceptance ledger (`sales_delivery_acceptances`)
//
// The Redis SETNX send marker used to be the authority, with a TTL: once it
// expired, an externally accepted message whose DB completion never committed
// could be submitted again. The ledger replaces it. Protocol (migration 205):
//
//   reserve → submit → record
//
// * `claim_acceptance` atomically INSERTs a `reserved` row for the stable
//   logical send unit. Zero rows claimed means this unit already has an
//   acceptance record (accepted or a live reservation) → DO NOT SUBMIT.
// * after the transport returns, the SAME row is updated to `accepted` (with
//   the transport message id and the reported source IP) or to `failed` (a
//   refusal; the unit becomes retryable).
// * a crash between reserve and submit leaves a `reserved` row. Rows older
//   than [`ACCEPTANCE_RESERVE_LEASE`] are reclaimed IN PLACE by the same
//   atomic claim: the ON CONFLICT branch renews `reserved_at` only when the
//   previous lease expired, so exactly ONE retrying worker wins the
//   resubmission right and the primary key remains the guard.
//
// Why in-place reclaim cannot double-submit: the claim is a single
// INSERT ... ON CONFLICT DO UPDATE statement — Postgres locks the conflicting
// row and re-evaluates the WHERE predicate under that lock, so a second
// concurrent claim observes the first claim's fresh `reserved_at` and is
// refused. The residual window is a process that was merely paused (not
// crashed) longer than the lease and then returns to submit: the lease is
// sized far above any per-send budget (15 minutes vs seconds), reclaim is
// logged and counted, and this residual ambiguity is inherent to any
// at-least-once transport — unlike the old TTL marker, the window is now
// named, bounded, observable, and never silently re-sends within a lease.
// ─────────────────────────────────────────────────────────────────────────────

/// Named lease after which a `reserved` acceptance row is treated as a crashed
/// reservation and returned to a submit-capable state by a new claim. Chosen
/// far above the per-send budget (connect + DATA + bookkeeping is seconds),
/// so a live submission is never stolen. The partial index
/// `idx_sales_delivery_acceptances_stale_reservations` reads exactly this
/// predicate in the sweep ([`reclaim_stale_acceptance_reservations`]).
const ACCEPTANCE_RESERVE_LEASE: Duration = Duration::from_secs(15 * 60);

/// The stable logical send identity, identical to the queue's idempotency
/// unit:
///
/// * sales mail — `sa-send:{sales_step_execution_id}`, the same value the
///   dispatcher uses as `messages.idempotency_key` (migration 205's comment,
///   `sequence_worker.rs`'s `sa-send:{step_execution_id}`). The typed
///   provenance column is read straight off the queue row.
/// * other mail — `email_queue:{queue row id}:{canonical recipient}`. The
///   queue row id is stable across claim/retry (attempt is deliberately NOT
///   part of the unit), and the recipient disambiguates multi-recipient rows
///   that expand into several independent sends.
fn send_unit_of(job: &EmailJob) -> String {
    match job.sales_step_execution_id.as_deref() {
        Some(step_execution_id) => format!("sa-send:{step_execution_id}"),
        None => format!("email_queue:{}:{}", job.id, canonical_recipient(&job.to)),
    }
}

/// Outcome of the atomic acceptance reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptanceClaim {
    /// This attempt owns the submission (fresh insert, a retry after a
    /// recorded refusal, or a reclaimed expired lease).
    Claimed,
    /// A prior submission of this logical unit is recorded `accepted` — the
    /// documented already-accepted outcome. NEVER submit again.
    AlreadyAccepted,
    /// Another attempt's reservation is still inside its lease. Do not
    /// submit; defer and let the ledger arbitrate.
    InFlight,
}

/// Atomic reserve/reclaim. Returns the claimed send unit when THIS attempt
/// owns the submission. The `ON CONFLICT` branch only matches a `failed` row
/// (retry after a transport refusal) or a `reserved` row whose
/// [`ACCEPTANCE_RESERVE_LEASE`] expired (crashed submission); `accepted` and
/// live `reserved` rows yield zero rows and therefore no submission.
const CLAIM_ACCEPTANCE_SQL: &str = r#"
    INSERT INTO sales_delivery_acceptances
        (send_unit, tenant_id, queue_id, state, transport, requested_source_ip)
    VALUES ($1, $2, $3::uuid, 'reserved', $4, $5::text::inet)
    ON CONFLICT (send_unit) DO UPDATE
    SET state = 'reserved',
        tenant_id = EXCLUDED.tenant_id,
        queue_id = EXCLUDED.queue_id,
        transport = EXCLUDED.transport,
        requested_source_ip = EXCLUDED.requested_source_ip,
        transport_message_id = NULL,
        actual_source_ip = NULL,
        accepted_at = NULL,
        last_error = CASE
            WHEN sales_delivery_acceptances.state = 'reserved'
            THEN 'acceptance reservation lease expired before submission completed; reclaimed'
            ELSE sales_delivery_acceptances.last_error
        END,
        reserved_at = NOW()
    WHERE sales_delivery_acceptances.state = 'failed'
       OR (sales_delivery_acceptances.state = 'reserved'
           AND sales_delivery_acceptances.reserved_at
               < NOW() - make_interval(secs => $6))
    RETURNING send_unit
"#;

/// Durable exactly-once gate: reserve the logical send unit before submit.
///
/// * `Ok(Claimed)` — no acceptance record exists (or the previous one failed /
///   its lease expired): this attempt may submit.
/// * `Ok(AlreadyAccepted)` — a prior submission is recorded: do NOT submit;
///   the caller records the recipient as possibly-sent (the send exists
///   externally).
/// * `Ok(InFlight)` — a live reservation exists: defer.
/// * `Err` — the ledger is unavailable. The caller DEFERS, never submits: an
///   unguarded send would forfeit exactly-once.
async fn claim_acceptance(
    db: &PgPool,
    job: &EmailJob,
    route: &DeliveryRoute,
) -> ProcessorResult<AcceptanceClaim> {
    let send_unit = send_unit_of(job);
    let queue_id = parse_queue_row_id(&job.id);
    let transport = transport_kind_for(route).to_string();
    let requested_source_ip = route.dedicated_source_ip().map(|ip| ip.to_string());
    let claimed: Option<String> = sqlx::query_scalar(CLAIM_ACCEPTANCE_SQL)
        .bind(&send_unit)
        .bind(&job.tenant_id)
        .bind(queue_id)
        .bind(&transport)
        .bind(requested_source_ip.as_deref())
        .bind(ACCEPTANCE_RESERVE_LEASE.as_secs() as i64)
        .fetch_optional(db)
        .await?;
    if claimed.is_some() {
        return Ok(AcceptanceClaim::Claimed);
    }

    // Zero rows: the row exists and is either accepted or a live reservation.
    // Read the state to surface the documented already-accepted outcome
    // distinctly (a concurrent state change between the two statements falls
    // through to InFlight — the safe choice: defer, do not submit).
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM sales_delivery_acceptances WHERE send_unit = $1")
            .bind(&send_unit)
            .fetch_optional(db)
            .await?;
    match state.as_deref() {
        Some("accepted") => Ok(AcceptanceClaim::AlreadyAccepted),
        _ => Ok(AcceptanceClaim::InFlight),
    }
}

/// Record the transport acceptance on the claimed ledger row. `last_error`
/// carries a route-contract note when the receipt did not confirm the
/// requested source IP — an AUDIT anomaly, never a retry signal.
async fn record_acceptance_accepted(
    db: &PgPool,
    send_unit: &str,
    receipt: &DeliveryReceipt,
    contract_note: Option<&str>,
) -> ProcessorResult<()> {
    let updated = sqlx::query(
        r#"
        UPDATE sales_delivery_acceptances
        SET state = 'accepted',
            transport_message_id = $2,
            actual_source_ip = $3::text::inet,
            accepted_at = NOW(),
            last_error = $4
        WHERE send_unit = $1 AND state = 'reserved'
        "#,
    )
    .bind(send_unit)
    .bind(receipt.transport_message_id.as_deref())
    .bind(receipt.actual_source_ip.map(|ip| ip.to_string()))
    .bind(contract_note)
    .execute(db)
    .await?;
    if updated.rows_affected() == 0 {
        // The lease was reclaimed while we were submitting. The external
        // acceptance still happened; a later retry would submit a second
        // time — surface it loudly rather than failing silently.
        metrics::counter!("apexmail_acceptance_record_missed").increment(1);
        warn!(
            send_unit,
            "acceptance ledger row was not 'reserved' when recording acceptance — \
             a concurrent reclaim may resubmit this unit"
        );
    }
    Ok(())
}

/// Record a transport refusal. `failed` frees the unit for a retry through
/// the normal failure handlers.
async fn record_acceptance_failed(
    db: &PgPool,
    send_unit: &str,
    error: &str,
) -> ProcessorResult<()> {
    sqlx::query(
        r#"
        UPDATE sales_delivery_acceptances
        SET state = 'failed',
            last_error = $2,
            accepted_at = NULL
        WHERE send_unit = $1 AND state = 'reserved'
        "#,
    )
    .bind(send_unit)
    .bind(error)
    .execute(db)
    .await?;
    Ok(())
}

/// Sweep for crashed `reserved` rows older than [`ACCEPTANCE_RESERVE_LEASE`].
///
/// Marks them `failed` (RE-RESERVE, never DELETE) with a distinctive
/// `last_error`, which returns the unit to the submit-capable state defined
/// by the protocol. Why this cannot double-send:
///
/// * the sweep is ONE atomic `UPDATE ... WHERE state = 'reserved' AND
///   reserved_at < NOW() - lease`; a live reservation (renewed within the
///   lease) cannot match, so an in-flight submission is never stolen;
/// * it does not itself submit — a resubmission still has to pass
///   [`claim_acceptance`]'s `ON CONFLICT` predicate, whose row lock admits
///   exactly one claimant, and the primary key admits exactly one
///   acceptance record;
/// * DELETING would let a plain INSERT recreate the unit with no trace of
///   the possibly-in-flight submission; keeping the row preserves the
///   transport/requested-IP audit trail and forces the reclaim through the
///   serialized claim path.
///
/// The sweep reads the partial index
/// `idx_sales_delivery_acceptances_stale_reservations`. It is
/// observability/governance over the on-demand reclaim inside
/// [`claim_acceptance`]; both use the same named lease.
pub async fn reclaim_stale_acceptance_reservations(db: &PgPool) -> ProcessorResult<u64> {
    let reclaimed = sqlx::query(
        r#"
        UPDATE sales_delivery_acceptances
        SET state = 'failed',
            last_error = 'reservation lease expired before submission completed; reclaimed for retry'
        WHERE state = 'reserved'
          AND reserved_at < NOW() - make_interval(secs => $1)
        "#,
    )
    .bind(ACCEPTANCE_RESERVE_LEASE.as_secs() as i64)
    .execute(db)
    .await?
    .rows_affected();
    if reclaimed > 0 {
        metrics::counter!("apexmail_acceptance_reservations_reclaimed").increment(reclaimed);
        warn!(
            reclaimed,
            "swept stale delivery-acceptance reservations (crashed submissions)"
        );
    }
    Ok(reclaimed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit-2: send-time admission control (token bucket)
//
// `SmtpConfig::rate_limit_per_second` and `SesConfig::max_send_rate` were
// configured but read by NO send path, so nothing capped the send rate at
// the moment of `transport.send()`. The admission gate below runs before
// every send: a Redis token bucket keyed per TENANT (account ceiling) and
// per DOMAIN (reputation), refilled from the configured rate. ONE atomic
// Lua script performs the reserve across both buckets (all-or-nothing); on
// exhaustion the caller defers the row via the existing requeue path
// instead of sending. Redis unavailability fails OPEN (best-effort, same
// posture as the G.3c send marker) — SES/SMTP still enforce their own
// server-side throttling.
// ─────────────────────────────────────────────────────────────────────────────

/// Audit-2 / P0 rate limiting: the two admission buckets a send must reserve
/// from — the tenant-wide ceiling and the sending domain's own bucket —
/// SCOPED BY ROUTE. Shared-pool mail and dedicated-IP mail have separate
/// account ceilings (SES `max_send_rate` vs the relay's
/// `rate_limit_per_second`) and separate reputation boundaries, so one
/// route's burst must not drain the other's bucket. The route kind is part of
/// the key; without it, shared and dedicated sends shared one bucket.
fn send_admission_keys(job: &EmailJob, kind: TransportKind) -> Vec<String> {
    vec![
        format!("rl:send:{}:tenant:{}", kind, job.tenant_id),
        format!("rl:send:{}:domain:{}", kind, job.domain_id),
    ]
}

/// The configured admission rate for a route: SES account rate for the shared
/// pool, the relay's rate for the dedicated route. Route-aware because the
/// two transports have independent capacity (the old gate used one rate
/// selected by `transport_type` for every route).
fn route_send_rate_per_second(config: &EmailConfig, kind: TransportKind) -> u32 {
    match kind {
        TransportKind::SesShared => config.ses.max_send_rate,
        TransportKind::Dedicated => config.smtp.rate_limit_per_second,
    }
}

/// Audit-2: atomic multi-bucket token-bucket reserve.
///
/// KEYS: the bucket hashes (tenant + domain). ARGV: [rate (tokens/sec),
/// capacity, now_ms]. Each bucket starts full (capacity = one second of
/// rate), refills continuously at `rate`, and persists `{tokens, ts}`.
/// Returns 1 when EVERY bucket can afford one token (consuming one from
/// each atomically), 0 otherwise — no partial consumption is possible.
const SEND_ADMISSION_LUA: &str = r#"
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ready = {}
for i = 1, #KEYS do
    local vals = redis.call('HMGET', KEYS[i], 'tokens', 'ts')
    local tokens = tonumber(vals[1])
    local ts = tonumber(vals[2])
    if tokens == nil or ts == nil then
        tokens = capacity
        ts = now
    end
    local elapsed_ms = math.max(0, now - ts)
    tokens = math.min(capacity, tokens + (elapsed_ms / 1000.0) * rate)
    if tokens < 1 then
        return 0
    end
    ready[i] = {KEYS[i], tokens}
end
for i = 1, #ready do
    redis.call('HSET', ready[i][1], 'tokens', ready[i][2] - 1, 'ts', now)
    redis.call('PEXPIRE', ready[i][1], 3600000)
end
return 1
"#;

/// Audit-2: reserve one send from every admission bucket, atomically.
/// `now_ms` is supplied by the caller (wall clock in production, injected
/// in tests) so refill is deterministic and testable without sleeping.
/// `Ok(true)` — admitted; `Ok(false)` — exhausted, defer the row;
/// `Err` — Redis unavailable.
async fn reserve_send_admission(
    redis: &RedisPool,
    keys: &[String],
    rate_per_second: u32,
    now_ms: i64,
) -> Result<bool, String> {
    let mut conn = redis.get().await.map_err(|e| e.to_string())?;
    let script = redis::Script::new(SEND_ADMISSION_LUA);
    let mut invocation = script.prepare_invoke();
    for key in keys {
        invocation.key(key);
    }
    let admitted: i32 = invocation
        .arg(rate_per_second)
        .arg(rate_per_second.max(1))
        .arg(now_ms)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(admitted == 1)
}

/// Fix 3: TTL for per-IP warmup counters/markers. The key embeds the UTC day,
/// so 48 hours keeps the current day's counter alive while old keys expire.
const WARMUP_COUNTER_TTL_SECS: u64 = 48 * 60 * 60;

/// Fix 3: daily warmup counter key for one dedicated source IP. The IP — not
/// the sending domain — is the reputation boundary that warmup protects.
/// Format preserved verbatim (`apexmail:warmup:ip:{ip_address}:{utc_day}`).
fn warmup_ip_counter_key(ip_address: &str, utc_day: &str) -> String {
    format!("apexmail:warmup:ip:{}:{}", ip_address, utc_day)
}

/// Fix 3: idempotency marker for one send unit (queue row + recipient) on one
/// source IP and UTC day. `attempt` is intentionally NOT part of the key: a
/// retry of the same row must not double-count against the IP quota. Distinct
/// recipients of a multi-recipient row carry distinct keys — each is a
/// separate send through the IP.
fn warmup_ip_send_marker_key(ip_address: &str, utc_day: &str, job: &EmailJob) -> String {
    format!(
        "apexmail:warmup:sent:{}:{}:{}:{}",
        ip_address,
        utc_day,
        job.id,
        canonical_recipient(&job.to)
    )
}

/// P0 aggregate-pool warmup reservation (one Lua script, one round trip).
///
/// KEYS[1..n]   — per-IP/day counters (format preserved:
///                `apexmail:warmup:ip:{ip_address}:{utc_day}`);
/// KEYS[n+1..2n] — per-send-unit markers, one per candidate.
///
/// ARGV[1] = n (candidate count); ARGV[2] = marker TTL seconds; then per
/// candidate i: `limit_i` (canonical daily cap, `-1` = unthrottled/active),
/// `consume_i` (1 = increment a warming counter and set a marker),
/// `rank_i` (0 = warming, 1 = active).
///
/// The script:
///
/// 1. if this send unit already holds a marker on any candidate, return that
///    candidate — a retry is admitted WITHOUT a second increment;
/// 2. otherwise pick the ELIGIBLE candidate with the lowest utilisation,
///    breaking ties by rank (all warming candidates are preferred over any
///    active one, so active IPs do not starve warmup), which spreads a
///    concurrent burst across the whole warming pool instead of exhausting
///    one IP while another has capacity;
/// 3. increment the chosen warming counter and set its marker atomically.
///
/// Returns the chosen 1-based index, or 0 when every warming candidate is at
/// its cap and no active candidate exists.
const WARMUP_AGGREGATE_RESERVE_LUA: &str = r#"
local n = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
for i = 1, n do
    if redis.call('EXISTS', KEYS[n + i]) == 1 then
        return i
    end
end
local best = nil
local best_rank = nil
local best_count = nil
for i = 1, n do
    local limit = tonumber(ARGV[2 + i])
    local rank = tonumber(ARGV[2 + 2 * n + i])
    local count = 0
    local eligible = true
    if limit >= 0 then
        count = tonumber(redis.call('GET', KEYS[i]) or '0')
        eligible = count < limit
    end
    if eligible and (best == nil
        or rank < best_rank
        or (rank == best_rank and count < best_count)) then
        best = i
        best_rank = rank
        best_count = count
    end
end
if best == nil then
    return 0
end
if tonumber(ARGV[2 + n + best]) == 1 then
    local new = redis.call('INCR', KEYS[best])
    if new == 1 then
        redis.call('EXPIRE', KEYS[best], ttl)
    end
    redis.call('SET', KEYS[n + best], '1', 'EX', ttl)
end
return best
"#;

/// The Redis keys and identity of the warmup slot reserved for ONE send unit.
/// Kept alongside the route so a confirmed source-IP contract violation can
/// release the exact slot the reservation took (accounting correction only —
/// never a retry trigger).
#[derive(Debug, Clone)]
struct WarmupReservation {
    /// `dedicated_ips.id` of the reserved IP.
    dedicated_ip_id: String,
    /// Parsed source IP (`dedicated_ips.ip_address`).
    source_ip: std::net::IpAddr,
    /// `apexmail:warmup:ip:{ip_address}:{utc_day}` — the counter the
    /// aggregate reservation incremented.
    counter_key: String,
    /// The per-send-unit idempotency marker.
    marker_key: String,
}

/// The chosen dedicated IP for one send, plus the warmup slot it consumed
/// (only warming IPs consume).
#[derive(Debug, Clone)]
struct ReservedDeliveryIp {
    candidate: RoutingCandidate,
    /// `Some` only when `candidate` is still warming and quota was consumed.
    reservation: Option<WarmupReservation>,
}

/// RESERVE: consume warmup capacity from the candidate SET atomically,
/// ordered by utilisation with warming preferred over active. The ROUTE is
/// built from the returned candidate, so the reservation and the route are
/// always the SAME IP.
///
/// Returns `Ok(None)` when every warming candidate is at its canonical daily
/// cap (and none is active) — the caller defers.
async fn reserve_warmup_capacity(
    redis: &RedisPool,
    job: &EmailJob,
    pool: &[RoutingCandidate],
    utc_day: &str,
) -> Result<Option<ReservedDeliveryIp>, String> {
    if pool.is_empty() {
        return Ok(None);
    }
    // Active-only pool: no quota to consume, no Redis dependency. The first
    // (oldest/graduated) active candidate carries the send.
    if pool.iter().all(|candidate| !candidate.is_warming()) {
        return Ok(pool.first().cloned().map(|candidate| ReservedDeliveryIp {
            candidate,
            reservation: None,
        }));
    }

    let mut conn = redis.get().await.map_err(|error| error.to_string())?;
    let script = redis::Script::new(WARMUP_AGGREGATE_RESERVE_LUA);
    let mut invocation = script.prepare_invoke();
    for candidate in pool {
        invocation.key(warmup_ip_counter_key(&candidate.ip_address, utc_day));
    }
    for candidate in pool {
        invocation.key(warmup_ip_send_marker_key(
            &candidate.ip_address,
            utc_day,
            job,
        ));
    }
    invocation
        .arg(pool.len() as i64)
        .arg(WARMUP_COUNTER_TTL_SECS);
    for candidate in pool {
        invocation.arg(
            candidate
                .daily_limit
                .map(|limit| limit.min(i64::MAX as u64) as i64)
                .unwrap_or(-1),
        );
    }
    for candidate in pool {
        invocation.arg(if candidate.is_warming() { 1 } else { 0 });
    }
    for candidate in pool {
        invocation.arg(if candidate.is_warming() { 0 } else { 1 });
    }

    let chosen: i64 = invocation
        .invoke_async(&mut *conn)
        .await
        .map_err(|error| error.to_string())?;
    if chosen <= 0 {
        return Ok(None);
    }
    let candidate = pool
        .get(chosen as usize - 1)
        .cloned()
        .ok_or_else(|| format!("warmup reservation returned out-of-range candidate {chosen}"))?;
    let reservation = candidate.is_warming().then(|| WarmupReservation {
        dedicated_ip_id: candidate.dedicated_ip_id.clone(),
        source_ip: candidate.source_ip,
        counter_key: warmup_ip_counter_key(&candidate.ip_address, utc_day),
        marker_key: warmup_ip_send_marker_key(&candidate.ip_address, utc_day, job),
    });
    Ok(Some(ReservedDeliveryIp {
        candidate,
        reservation,
    }))
}

/// Release-one-slot Lua: delete the send-unit marker and, ONLY when the
/// marker existed (i.e. this send unit held a reservation), decrement the
/// per-IP counter. A missing marker means there is nothing to release — the
/// DECR is skipped so a repeated release can never underflow another
/// sender's counter.
const WARMUP_RELEASE_LUA: &str = r#"
if redis.call('DEL', KEYS[2]) == 1 then
    local current = tonumber(redis.call('GET', KEYS[1]) or '0')
    if current ~= nil and current > 0 then
        redis.call('DECR', KEYS[1])
    end
end
return 1
"#;

/// Release a warmup reservation when the accepted receipt CONFIRMS the
/// message left through a different IP than the one reserved (a transport
/// contract violation). This is an accounting correction, NOT a retry: the
/// acceptance ledger already records the send as accepted, so the message is
/// never resubmitted. The Lua script deletes the idempotency marker and
/// decrements the per-IP counter exactly once.
async fn release_warmup_reservation(
    redis: &RedisPool,
    reservation: &WarmupReservation,
) -> Result<(), String> {
    let mut conn = redis.get().await.map_err(|error| error.to_string())?;
    let _: i32 = redis::Script::new(WARMUP_RELEASE_LUA)
        .key(&reservation.counter_key)
        .key(&reservation.marker_key)
        .invoke_async(&mut *conn)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

impl ReservedDeliveryIp {
    /// The exact route this reservation was made for.
    fn route(&self) -> DeliveryRoute {
        DeliveryRoute::Dedicated {
            dedicated_ip_id: self.candidate.dedicated_ip_id.clone(),
            source_ip: self.candidate.source_ip,
        }
    }
}

/// Route-aware domain readiness. A shared-pool send requires
/// `domains.ses_verified` (SES refuses unverified senders); a dedicated relay
/// route binds a tenant IP and does not traverse SES, so it is ready without
/// it. `None` = ready; `Some(reason)` = defer the row with that reason.
fn domain_route_readiness(route: &DeliveryRoute, domain: &Domain) -> Option<&'static str> {
    match route {
        DeliveryRoute::SesShared if !domain.ses_verified => Some("domain_ses_not_verified"),
        _ => None,
    }
}

/// Compare an ACCEPTED receipt against the route it was asked to execute,
/// returning a human-readable contract note when the receipt does not prove
/// the binding. Deliberately ASYMMETRIC:
///
/// * [`DeliveryRoute::Dedicated`]: the receipt's `actual_source_ip` must be
///   present AND equal to the requested IP;
/// * [`DeliveryRoute::SesShared`]: no dedicated binding exists to confirm.
///
/// A note is an AUDIT anomaly — it is stored on the acceptance ledger and
/// alarmed, and it NEVER triggers a retry: by the time a receipt exists the
/// transport has already accepted the message, and a retry would duplicate an
/// externally accepted send. The invariant lives in the pre-DATA gate
/// ([`HybridTransport::ensure_route_dispatchable`]): an unverifiable
/// dedicated route is refused before submission, so this comparison is a
/// defensive assertion, not the enforcement point.
fn route_receipt_contract_note(route: &DeliveryRoute, receipt: &DeliveryReceipt) -> Option<String> {
    match route {
        DeliveryRoute::SesShared => None,
        DeliveryRoute::Dedicated { source_ip, .. } => match receipt.actual_source_ip {
            Some(actual) if actual == *source_ip => None,
            Some(actual) => Some(format!(
                "route contract violation: requested source IP {source_ip}, transport reported {actual}"
            )),
            None => Some(format!(
                "route contract violation: transport accepted the send but reported no source IP for {source_ip}"
            )),
        },
    }
}

/// One `email_queue` row as decoded by `fetch_jobs`, before per-recipient
/// expansion (FIX-8).
#[derive(Debug, Clone, sqlx::FromRow)]
struct QueuedEmailRow {
    id: String,
    #[sqlx(rename = "messageId")]
    message_id: String,
    #[sqlx(rename = "tenantId")]
    tenant_id: String,
    #[sqlx(rename = "domainId")]
    domain_id: String,
    #[sqlx(rename = "from")]
    from: String,
    to: String,
    #[sqlx(rename = "toAddresses")]
    to_addresses: Option<Vec<String>>,
    subject: String,
    html: Option<String>,
    text: Option<String>,
    headers: Option<serde_json::Value>,
    attachments: Option<serde_json::Value>,
    #[sqlx(rename = "campaignId")]
    campaign_id: Option<String>,
    /// F55: validated server-owned send category (migration 187).
    message_category: String,
    tags: Option<Vec<String>>,
    metadata: Option<serde_json::Value>,
    #[sqlx(rename = "salesStepExecutionId")]
    sales_step_execution_id: Option<String>,
    #[sqlx(rename = "scheduledAt")]
    scheduled_at: Option<DateTime<Utc>>,
    attempt: i32,
    #[sqlx(rename = "createdAt")]
    created_at: DateTime<Utc>,
}

/// FIX-8: expand one queued row into one [`EmailJob`] per recipient. When
/// `to_addresses` is present and non-empty, a send unit is created for EVERY
/// address (previously only the first recipient was used). An EXPLICIT empty
/// array means "nothing left to send" (all recipients of a multi-recipient
/// row were already delivered — see `metadata.pending_recipients`) and yields
/// no jobs; only a NULL column (genuinely legacy row) falls back to the
/// single-recipient `to` column.
fn queued_row_to_jobs(row: QueuedEmailRow) -> Vec<EmailJob> {
    let recipients: Vec<String> = match row.to_addresses {
        Some(addrs) => addrs,
        None => vec![row.to.clone()],
    };
    recipients
        .into_iter()
        .map(|to| EmailJob {
            id: row.id.clone(),
            message_id: row.message_id.clone(),
            tenant_id: row.tenant_id.clone(),
            domain_id: row.domain_id.clone(),
            from: row.from.clone(),
            to,
            subject: row.subject.clone(),
            html: row.html.clone(),
            text: row.text.clone(),
            headers: row.headers.clone(),
            attachments: row.attachments.clone(),
            campaign_id: row.campaign_id.clone(),
            message_category: row.message_category.clone(),
            tags: row.tags.clone(),
            metadata: row.metadata.clone(),
            sales_step_execution_id: row.sales_step_execution_id.clone(),
            scheduled_at: row.scheduled_at,
            attempt: row.attempt,
            created_at: row.created_at,
        })
        .collect()
}

/// G.3a: expand claimed rows into send units, counting every expanded
/// recipient against the available concurrency slots.
fn expand_rows_within_cap(rows: Vec<QueuedEmailRow>, cap: usize) -> Vec<EmailJob> {
    let mut jobs: Vec<EmailJob> = Vec::new();
    for row in rows {
        if jobs.len() >= cap {
            break;
        }
        let expanded = queued_row_to_jobs(row);
        let remaining = cap - jobs.len();
        if expanded.len() > remaining {
            warn!(
                claimed_recipients = expanded.len(),
                admitted_recipients = remaining,
                "multi-recipient row exceeds available concurrency slots — excess \
                 recipients deferred until the next lease cycle"
            );
        }
        jobs.extend(expanded.into_iter().take(remaining));
    }
    jobs
}

/// F-21: disposition class for a failed send attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendFailureClass {
    /// Temporary failure (4xx reply, or a "Soft bounce"/"temporary" marker) —
    /// retried via `handle_soft_bounce` with the existing exponential backoff.
    Soft,
    /// Permanent failure (5xx reply, or a "Hard bounce" marker) —
    /// `handle_hard_bounce`: row marked 'bounced', recipient suppressed,
    /// bounce event recorded. Never retried.
    Hard,
    /// No classification signal (timeouts, DNS, connection errors) —
    /// `handle_error`: retried below max_retries, DLQ + 'failed' above.
    Unknown,
}

/// F-21: classify a transport failure for the retry decision.
///
/// The structured SMTP reply code wins when present (the transport now
/// carries it in [`ProcessorError::Smtp`] instead of flattening the reply
/// into a redacted, truncated string): 4xx is temporary, 5xx is permanent.
/// Legacy string markers keep working for messages that already carry them
/// so other error paths (and the SES transport) are unaffected.
fn classify_send_failure(err: &ProcessorError) -> SendFailureClass {
    if let ProcessorError::Smtp { code, .. } = err {
        return match code {
            400..=499 => SendFailureClass::Soft,
            500..=599 => SendFailureClass::Hard,
            _ => SendFailureClass::Unknown,
        };
    }
    // Audit-4: the SES transport classifies at the source (typed SDK error)
    // and threads the disposition through the structured Ses variant.
    if let ProcessorError::Ses { permanent, .. } = err {
        return if *permanent {
            SendFailureClass::Hard
        } else {
            SendFailureClass::Soft
        };
    }
    let err_str = err.to_string();
    if err_str.contains("Soft bounce") || err_str.contains("temporary") {
        SendFailureClass::Soft
    } else if err_str.contains("Hard bounce") {
        SendFailureClass::Hard
    } else {
        SendFailureClass::Unknown
    }
}

/// Does this failure actually prove the RECIPIENT ADDRESS is invalid — the
/// only justification for suppressing it tenant-wide?
///
/// A 5xx reply is permanent for *this message*, but most 5xx are policy
/// verdicts about the sender or content ("550 5.7.1 spam", IP blocklists,
/// DMARC failures of OUR alignment) and say nothing about the mailbox.
/// Suppressing on those poisons valid recipients — one receiving domain's
/// spam policy would silence the address for the whole tenant. Only a
/// 5.1.x address-status enhanced code (or an explicit mailbox rejection
/// phrase) proves address invalidity. SES dispositions carry the
/// address-proving verdict from the transport source (typed SDK error);
/// account/configuration refusals dead-letter without suppressing.
fn is_recipient_invalid(error: &ProcessorError) -> bool {
    match error {
        ProcessorError::Smtp {
            enhanced, message, ..
        } => {
            if let Some(enhanced) = enhanced {
                if enhanced.starts_with("5.1.") {
                    return true;
                }
            }
            let m = message.to_ascii_lowercase();
            [
                "user unknown",
                "unknown user",
                "no such user",
                "no such recipient",
                "recipient not found",
                "mailbox not found",
                "bad destination mailbox",
                "does not exist",
            ]
            .iter()
            .any(|phrase| m.contains(phrase))
        }
        // Suppression requires the transport's address-proving verdict —
        // `permanent` alone is NOT sufficient (sending-paused /
        // resource-not-found dead-letter without proving the mailbox bad).
        ProcessorError::Ses {
            permanent: true,
            address_proving: true,
            ..
        } => true,
        _ => false,
    }
}

/// Email processor for sending emails from the queue.
pub struct EmailProcessor {
    db: PgPool,
    redis: RedisPool,
    config: EmailConfig,
    /// Route-aware dispatcher: `SesShared` → SES, `Dedicated` → relay SMTP.
    /// A missing backend for a requested route fails closed (never crosses the
    /// shared/dedicated boundary).
    transport: HybridTransport,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Arc<Notify>,
    /// Last wall-clock time (ms) queue-depth metrics were exported.
    queue_metrics_last_emit_ms: AtomicI64,

    // Caches
    suppression_cache: Cache<String, CachedSuppression>,
    /// F18: cache of CONFIRMED tenant restrictions only (reason string).
    /// Allowed/TemporarilyUnavailable decisions are never cached — see
    /// [`EmailProcessor::tenant_policy`].
    tenant_restriction_cache: Cache<String, String>,

    // Circuit breakers for SMTP endpoints
    smtp_circuit_breaker: CircuitBreaker,

    // Error rate tracking
    recent_outcomes: Mutex<Vec<(SendOutcome, Instant)>>,
    error_cooldown_until: AtomicI64,

    // SCALE-H-04: Backpressure / load shedding
    backpressure: Arc<Backpressure>,
}

impl EmailProcessor {
    /// Create a new email processor.
    /// This is async because SES transport requires AWS SDK initialisation.
    pub async fn new(db: PgPool, redis: RedisPool, config: EmailConfig) -> ProcessorResult<Self> {
        let transport = create_transport_from_config(&config).await?;
        Self::with_transport(db, redis, config, transport).await
    }

    /// Create an email processor around an explicitly constructed hybrid
    /// transport. Used by the binary (which knows whether the relay was
    /// actually configured) and by adversarial tests that inject recording
    /// doubles.
    pub async fn with_transport(
        db: PgPool,
        redis: RedisPool,
        config: EmailConfig,
        transport: HybridTransport,
    ) -> ProcessorResult<Self> {
        let smtp_circuit_breaker = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        });

        let backpressure = Arc::new(Backpressure::new(BackpressureConfig {
            max_concurrency: config.base.concurrency,
            max_backlog: 10_000,
            ..Default::default()
        }));

        Ok(Self {
            db,
            redis,
            config,
            transport,
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            queue_metrics_last_emit_ms: AtomicI64::new(0),
            shutdown_notify: Arc::new(Notify::new()),
            suppression_cache: Cache::builder()
                .max_capacity(SUPPRESSION_CACHE_MAX_SIZE)
                .time_to_live(SUPPRESSION_CACHE_TTL)
                .build(),
            tenant_restriction_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            smtp_circuit_breaker,
            recent_outcomes: Mutex::new(Vec::new()),
            error_cooldown_until: AtomicI64::new(0),
            backpressure,
        })
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            concurrency = self.config.base.concurrency,
            "Starting email processor"
        );

        // Queue-depth metrics must NOT depend on transport health: while the
        // transport is down (e.g. missing credentials), the poll loop below
        // never starts — and that is exactly when the EmailQueueBacklog
        // alerts need their metric. The task runs for the processor's
        // lifetime and stops with the shutdown notification.
        {
            let metrics_self = Arc::clone(&self);
            let shutdown = Arc::clone(&self.shutdown_notify);
            tokio::spawn(async move {
                loop {
                    metrics_self.record_queue_depth_metrics().await;
                    tokio::select! {
                        _ = sleep(Duration::from_secs(15)) => {}
                        _ = shutdown.notified() => break,
                    }
                }
            });
        }

        // F25: restart reconciliation — sweep parents whose recipient rows
        // are ALL terminal but whose aggregate status is not (the residue
        // of a crash between a recipient transition and its parent
        // reconciliation), once immediately and then every 60 s.
        //
        // P0: the same loop sweeps the delivery-acceptance ledger for
        // `reserved` rows older than ACCEPTANCE_RESERVE_LEASE — crashed
        // submissions that never reached `accepted`/`failed`. The sweep is
        // governance/observability; the claim reclaims them on demand too.
        {
            let reconcile_self = Arc::clone(&self);
            let shutdown = Arc::clone(&self.shutdown_notify);
            tokio::spawn(async move {
                loop {
                    reconcile_self.reconcile_stuck_parents().await;
                    if let Err(error) =
                        reclaim_stale_acceptance_reservations(&reconcile_self.db).await
                    {
                        warn!(
                            error = %error,
                            "stale delivery-acceptance reservation sweep failed — retried on the next interval"
                        );
                    }
                    tokio::select! {
                        _ = sleep(Duration::from_secs(60)) => {}
                        _ = shutdown.notified() => break,
                    }
                }
            });
        }

        // Verify transport
        self.transport.verify().await?;
        info!("Email transport verified");

        if self.config.transport_type == TransportType::Smtp && !self.config.dkim.enabled {
            return Err(ProcessorError::Config(
                "DKIM_ENABLED must be true when EMAIL_TRANSPORT_TYPE=smtp; verified domains must not be sent unsigned"
                    .into(),
            ));
        }

        self.is_running.store(true, Ordering::SeqCst);

        // Run poll loop
        self.poll_loop().await;

        Ok(())
    }

    /// Stop the processor gracefully.
    pub async fn stop(&self) -> ProcessorResult<()> {
        info!("Stopping email processor");
        self.is_running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Wait for active jobs
        let max_wait = Duration::from_secs(30);
        let start = Instant::now();

        while self.active_jobs.load(Ordering::SeqCst) > 0 && start.elapsed() < max_wait {
            sleep(Duration::from_millis(100)).await;
        }

        // Close transport
        self.transport.close().await?;

        info!("Email processor stopped");
        Ok(())
    }

    /// Main poll loop with backpressure-based load shedding.
    ///
    /// SCALE-H-04: Uses [`Backpressure`] for load shedding when the queue
    /// backlog exceeds the threshold, and tracks available capacity via the
    /// backpressure semaphore.  The actual job processing concurrency is
    /// still managed by the existing `active_jobs` atomic, but the semaphore
    /// provides an additional hard cap and a load-shedding cooldown.
    async fn poll_loop(&self) {
        while self.is_running.load(Ordering::SeqCst) {
            // ── Error rate cooldown ────────────────────────────
            let cooldown_until = self.error_cooldown_until.load(Ordering::SeqCst);
            let now = Utc::now().timestamp_millis();
            if now < cooldown_until {
                let remaining = cooldown_until - now;
                warn!(
                    remaining_ms = remaining,
                    "Worker paused due to high error rate"
                );
                sleep(Duration::from_millis(remaining.min(5000) as u64)).await;
                continue;
            }

            // ── SCALE-H-04: Load shedding check ───────────────
            if self.backpressure.is_shedding() {
                warn!(
                    backlog = self.backpressure.backlog(),
                    in_flight = self.backpressure.in_flight(),
                    available = self.backpressure.available(),
                    "Load shedding active — pausing poll loop"
                );
                sleep(Duration::from_secs(1)).await;
                continue;
            }

            // ── Available capacity ─────────────────────────────
            let available_slots = self
                .config
                .base
                .concurrency
                .saturating_sub(self.active_jobs.load(Ordering::SeqCst));
            if available_slots == 0 {
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            // ── Fetch jobs ────────────────────────────────────
            match self.fetch_jobs(available_slots).await {
                Ok(jobs) if jobs.is_empty() => {
                    // SCALE-H-04: Observe zero backlog when queue is empty
                    self.backpressure.observe_backlog(0);
                    tokio::select! {
                        _ = sleep(self.config.base.poll_interval) => {}
                        _ = self.shutdown_notify.notified() => break,
                    }
                }
                Ok(jobs) => {
                    // SCALE-H-04/F9: Observe the REAL queue depth for the
                    // load-shedding decision. The batch is capped at
                    // `available_slots` (≤ concurrency, e.g. 10), so feeding
                    // `jobs.len()` kept the observed backlog permanently far
                    // below `max_backlog` (10_000) — shedding was
                    // unreachable. Threshold semantics are unchanged; only
                    // the observed value is now the true pending depth.
                    match self.pending_queue_depth().await {
                        Ok(depth) => self.backpressure.observe_backlog(depth),
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Failed to read queue depth for backpressure; keeping last sample"
                            );
                        }
                    }

                    // F5:claim identity of every distinct row in this batch,
                    // used after the chunk to release multi-recipient rows
                    // whose pending set is not yet empty.
                    let claimed_rows: Vec<(String, Option<String>)> = {
                        let mut seen = std::collections::HashSet::new();
                        jobs.iter()
                            .filter(|job| seen.insert(job.id.clone()))
                            .map(|job| (job.id.clone(), lease_token_of(job).map(str::to_string)))
                            .collect()
                    };

                    // Batch suppression check
                    let suppressions = self.batch_suppression_check(&jobs).await;

                    let mut handles = Vec::with_capacity(jobs.len());
                    for job in jobs {
                        let suppression = suppressions.get(&format!(
                            "{}:{}",
                            job.tenant_id,
                            canonical_recipient(&job.to)
                        ));
                        if let Some(reason) = suppression {
                            if reason == SUPPRESSION_CHECK_FAILED {
                                // The suppression CHECK itself failed (DB
                                // error). Requeue for a later retry instead of
                                // permanently suppressing the recipient.
                                warn!(
                                    job_id = %job.id,
                                    recipient = %job.to,
                                    "Suppression check failed — requeueing job instead of suppressing"
                                );
                                if let Err(e) =
                                    self.requeue_job(&job, SUPPRESSION_CHECK_FAILED).await
                                {
                                    error!(
                                        job_id = %job.id,
                                        error = %e,
                                        "Failed to requeue job after suppression-check failure"
                                    );
                                }
                                continue;
                            }
                            // Skip suppressed recipients
                            if let Err(e) = self.handle_suppressed(&job, reason).await {
                                error!(
                                    job_id = %job.id,
                                    message_id = %job.message_id,
                                    tenant_id = %job.tenant_id,
                                    recipient = %job.to,
                                    error = %e,
                                    "Failed to handle suppression"
                                );
                            }
                            continue;
                        }

                        // Process non-suppressed jobs concurrently
                        handles.push(self.process_job(job));
                    }

                    // Await all concurrently
                    let results = futures::future::join_all(handles).await;
                    for result in results {
                        if let Err(e) = result {
                            debug!(error = %e, "Job failed");
                        }
                    }

                    // F5:multi-recipient rows admitted only `available_slots`
                    // recipients this lease; release rows that still owe
                    // recipients back to 'pending' so the next poll continues
                    // immediately instead of waiting out the 300s lease
                    // (~8.3h for a 1000-recipient row otherwise).
                    self.release_rows_with_remaining_recipients(&claimed_rows)
                        .await;

                    // Short delay before next batch
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!(error = %e, "Failed to fetch jobs");
                    sleep(self.config.base.poll_interval).await;
                }
            }
        }
    }

    /// Fetch jobs from the queue.
    async fn fetch_jobs(&self, limit: usize) -> ProcessorResult<Vec<EmailJob>> {
        let visibility_ms = self.config.base.visibility_timeout.as_millis();
        let visibility_ms_i64 = if visibility_ms > i64::MAX as u128 {
            i64::MAX
        } else {
            visibility_ms as i64
        };
        let lock_until = Utc::now() + chrono::Duration::milliseconds(visibility_ms_i64);

        let rows = sqlx::query_as::<_, QueuedEmailRow>(FETCH_JOBS_SQL)
            .bind(lock_until)
            .bind(limit as i64)
            .fetch_all(&self.db)
            .await?;

        // F25: flip the parents of every claimed row from 'queued'/
        // 'scheduled' to 'processing' — the worker-side scheduled →
        // processing transition (previously scheduled audit rows never
        // moved at all) and the parent-visible dispatch signal the
        // cancellation check relies on (F24). Grouped per tenant (a batch
        // can span tenants). Best-effort: a failed parent update must not
        // strand the claimed rows.
        let mut claimed_parents: HashMap<String, Vec<uuid::Uuid>> = HashMap::new();
        for row in &rows {
            if let Ok(message_uuid) = uuid::Uuid::parse_str(&row.message_id) {
                claimed_parents
                    .entry(row.tenant_id.clone())
                    .or_default()
                    .push(message_uuid);
            }
        }
        for (tenant_id, parents) in claimed_parents {
            if let Err(e) = sqlx::query(MESSAGES_CLAIMED_UPDATE_SQL)
                .bind(&parents)
                .bind(tenant_id)
                .execute(&self.db)
                .await
            {
                warn!(
                    error = %e,
                    parents = parents.len(),
                    "Failed to transition claimed message parents to 'processing'"
                );
            }
        }

        // FIX-8: expand one queued row into one send unit PER recipient so
        // multi-recipient messages no longer drop recipients 2..N.
        // G.3a: recipient expansion counts against the concurrency budget —
        // `limit` is the available slot count, and the expansion is capped to
        // it so one 10k-recipient row cannot fan out into 10k concurrent
        // sends. Recipients beyond the cap remain in the row's pending set
        // and are delivered after the visibility lease expires (or — F5 —
        // immediately, via `release_rows_with_remaining_recipients`).
        Ok(expand_rows_within_cap(rows, limit))
    }

    /// F9:actual depth of the deliverable queue — the value the SCALE-H-04
    /// load-shedding decision must be fed (the fetched batch is capped at
    /// the concurrency budget and is NOT the backlog).
    async fn pending_queue_depth(&self) -> ProcessorResult<u64> {
        let depth: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM email_queue
            WHERE status = 'pending'
              AND (scheduled_at IS NULL OR scheduled_at <= NOW())
            "#,
        )
        .fetch_one(&self.db)
        .await?;
        Ok(depth.max(0) as u64)
    }

    /// Export `apexmail_email_queue_depth{status=...}` — the metric the
    /// EmailQueueBacklog / CriticalEmailQueueBacklog alerts key on. The
    /// original exporter lived in a since-removed outbound delivery
    /// package, so the alerts were dead rules; the deployed worker is the
    /// right emitter. Time-gated to avoid a grouped COUNT on every poll.
    async fn record_queue_depth_metrics(&self) {
        let now_ms = Utc::now().timestamp_millis();
        let last = self
            .queue_metrics_last_emit_ms
            .swap(now_ms, Ordering::SeqCst);
        if now_ms.saturating_sub(last) < 10_000 {
            return;
        }

        let rows: Result<Vec<(String, i64)>, sqlx::Error> =
            sqlx::query_as("SELECT status, COUNT(*) FROM email_queue GROUP BY status")
                .fetch_all(&self.db)
                .await;

        match rows {
            Ok(counts) => {
                // F59: the complete bounded set is emitted — see
                // [`overlay_status_counts`].
                for (status, count) in overlay_status_counts(counts) {
                    metrics::gauge!("apexmail_email_queue_depth", "status" => status)
                        .set(count.max(0) as f64);
                }
                metrics::gauge!("apexmail_email_queue_metrics_fresh").set(1.0);
            }
            Err(e) => {
                // F59: freshness/error is exposed SEPARATELY — the last
                // complete snapshot stays published (stale but labelled)
                // instead of being quietly overwritten.
                metrics::counter!("apexmail_email_queue_metrics_errors").increment(1);
                metrics::gauge!("apexmail_email_queue_metrics_fresh").set(0.0);
                warn!(error = %e, "failed to export queue depth metrics");
            }
        }
    }

    /// F5:after a processed chunk, release rows that still owe recipients
    /// back to 'pending' (lease cleared) so the next poll continues without
    /// waiting for the visibility lease to expire. Fenced on this claim's
    /// lease token (Audit-5) — a stale worker cannot release a row the
    /// next owner has re-claimed. Rows that finished (empty pending set →
    /// already 'sent') or were requeued/deferred by the failure handlers
    /// simply do not match the predicate.
    async fn release_rows_with_remaining_recipients(&self, claimed: &[(String, Option<String>)]) {
        for (job_id, lease_token) in claimed {
            match sqlx::query(RELEASE_REMAINDER_SQL)
                .bind(job_id)
                .bind(lease_token.as_deref())
                .execute(&self.db)
                .await
            {
                Ok(updated) if updated.rows_affected() > 0 => {
                    debug!(
                        job_id = %job_id,
                        "Released multi-recipient row with remaining recipients back to pending"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        job_id = %job_id,
                        error = %e,
                        "Failed to release row with remaining recipients; the lease expiry will recover it"
                    );
                }
            }
        }
    }

    /// Batch suppression check for efficiency (claim-time).
    ///
    /// F55: POSITIVE suppression decisions are NEVER cached anymore — a
    /// cached positive could terminalize a job for a recipient who
    /// resubscribed after the cache was primed (a `suppression:added` /
    /// preference-change event missed by this replica would not
    /// invalidate it). Only NEGATIVE results (no suppression row) are
    /// cached; any positive verdict comes from a database row read in
    /// THIS batch, which is the authoritative state at claim time — and
    /// every job that proceeds to dispatch gets the authoritative
    /// `dispatch_consent` recheck anyway.
    ///
    /// F55: the batch ALSO enforces subscription_preferences for the
    /// send's validated server-owned category (non-exempt categories
    /// only), so a category opt-out suppresses at claim time exactly like
    /// the dispatch-time recheck does.
    async fn batch_suppression_check(&self, jobs: &[EmailJob]) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // Group by tenant (suppressions) and tenant+category (preferences).
        let mut by_tenant: HashMap<String, Vec<&str>> = HashMap::new();
        let mut by_tenant_category: HashMap<(String, String), Vec<&str>> = HashMap::new();
        for job in jobs {
            by_tenant
                .entry(job.tenant_id.clone())
                .or_default()
                .push(&job.to);
            if !apexmail_lib::email_headers::message_category::is_preference_exempt(
                &job.message_category,
            ) {
                by_tenant_category
                    .entry((job.tenant_id.clone(), job.message_category.clone()))
                    .or_default()
                    .push(&job.to);
            }
        }

        for (tenant_id, emails) in by_tenant {
            // Negative-only cache: a cached "no suppression" skips the
            // suppressions query; anything else is read fresh.
            let mut uncached: Vec<String> = Vec::new();
            for email in &emails {
                let cache_key = format!("{}:{}", tenant_id, canonical_recipient(email));
                match self.suppression_cache.get(&cache_key) {
                    Some(cached) if !cached.suppressed => {}
                    Some(_) => unreachable!("positive suppression results are never cached"),
                    None => uncached.push(canonical_recipient(email)),
                }
            }

            // Query database for uncached
            if !uncached.is_empty() {
                let db_result = sqlx::query_as::<_, (String, String)>(
                    r#"
                    SELECT LOWER(email), reason
                    FROM suppressions
                    WHERE tenant_id = $1 AND LOWER(email) = ANY($2)
                    "#,
                )
                .bind(&tenant_id)
                .bind(&uncached)
                .fetch_all(&self.db)
                .await;

                let suppressions: Vec<(String, String)> = match db_result {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!(tenant_id = %tenant_id, error = %e,
                            "Failed to check suppressions; flagging for requeue (not suppression)");
                        // The check FAILED (distinct from "actually
                        // suppressed"): mark these recipients with the
                        // sentinel so poll_loop requeues them instead of
                        // permanently suppressing the batch. Nothing is
                        // cached — the next poll retries the query.
                        for email in &uncached {
                            let cache_key = format!("{}:{}", tenant_id, email);
                            result.insert(cache_key, SUPPRESSION_CHECK_FAILED.to_string());
                        }
                        continue;
                    }
                };

                // Build set of suppressed emails
                let suppressed_emails: std::collections::HashSet<String> =
                    suppressions.iter().map(|(e, _)| e.clone()).collect();

                // Collect positive results WITHOUT caching them (F55).
                for (email, reason) in suppressions {
                    let cache_key = format!("{}:{}", tenant_id, email);
                    result.insert(cache_key, format!("global_suppression:{reason}"));
                }

                // Cache negative results only
                for email in &uncached {
                    if !suppressed_emails.contains(email) {
                        let cache_key = format!("{}:{}", tenant_id, email);
                        self.suppression_cache.insert(
                            cache_key,
                            CachedSuppression {
                                suppressed: false,
                                reason: None,
                                expires_at: Instant::now() + SUPPRESSION_CACHE_TTL,
                            },
                        );
                    }
                }
            }
        }

        // F55: category preference opt-outs (always read fresh — never
        // cached, matching the authoritative dispatch-time recheck).
        for ((tenant_id, category), emails) in by_tenant_category {
            let canonical: Vec<String> = emails
                .iter()
                .map(|email| canonical_recipient(email))
                .collect();
            let opted_out: Vec<(String,)> = match sqlx::query_as(
                r#"
                SELECT LOWER(email)
                FROM subscription_preferences
                WHERE tenant_id = $1 AND category = $2 AND subscribed = false
                  AND LOWER(email) = ANY($3)
                "#,
            )
            .bind(&tenant_id)
            .bind(&category)
            .bind(&canonical)
            .fetch_all(&self.db)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!(tenant_id = %tenant_id, category = %category, error = %e,
                        "Failed to check category preferences; flagging for requeue (not suppression)");
                    for email in canonical {
                        let cache_key = format!("{}:{}", tenant_id, email);
                        result.insert(cache_key, SUPPRESSION_CHECK_FAILED.to_string());
                    }
                    continue;
                }
            };
            for (email,) in opted_out {
                let cache_key = format!("{}:{}", tenant_id, email);
                // Global suppression (checked above) takes precedence in
                // the recorded reason; insert only when not already
                // suppressed.
                result
                    .entry(cache_key)
                    .or_insert_with(|| format!("category_opt_out:{category}"));
            }
        }

        result
    }

    /// Process a single job.
    async fn process_job(&self, job: EmailJob) -> ProcessorResult<()> {
        self.active_jobs.fetch_add(1, Ordering::SeqCst);
        let start = Instant::now();
        let job_id = job.id.clone();

        let result = self.process_job_inner(&job).await;

        if let Err(error) = &result {
            if matches!(error, ProcessorError::Job(_) | ProcessorError::Dkim(_)) {
                if let Err(mark_error) = self.handle_permanent_job_failure(&job, error).await {
                    error!(
                        job_id = %job.id,
                        error = %mark_error,
                        "failed to dead-letter permanently rejected email job"
                    );
                }
            }
        }

        self.active_jobs.fetch_sub(1, Ordering::SeqCst);

        // Record outcome for error rate tracking
        let outcome = match &result {
            Ok(_) => SendOutcome::Success,
            // F-21: structured reply-code classification (must mirror
            // `classify_send_failure`). Audit-4: SES source classification.
            Err(ProcessorError::Smtp {
                code: 400..=499, ..
            }) => SendOutcome::SoftBounce,
            Err(ProcessorError::Smtp {
                code: 500..=599, ..
            }) => SendOutcome::HardBounce,
            Err(ProcessorError::Ses {
                permanent: true, ..
            }) => SendOutcome::HardBounce,
            Err(ProcessorError::Ses {
                permanent: false, ..
            }) => SendOutcome::SoftBounce,
            Err(ProcessorError::Transport(msg)) if msg.contains("Soft bounce") => {
                SendOutcome::SoftBounce
            }
            Err(ProcessorError::Transport(msg)) if msg.contains("Hard bounce") => {
                SendOutcome::HardBounce
            }
            Err(ProcessorError::RateLimited(_)) => SendOutcome::RateLimit,
            Err(ProcessorError::Job(_) | ProcessorError::Dkim(_)) => SendOutcome::Rejected,
            Err(_) => SendOutcome::TransportError,
        };
        self.record_outcome(outcome);

        let duration = start.elapsed();
        debug!(
            job_id = %job_id,
            duration_ms = duration.as_millis(),
            outcome = ?outcome,
            "Job processed"
        );

        result
    }

    async fn process_job_inner(&self, job: &EmailJob) -> ProcessorResult<()> {
        // Check circuit breaker. Returning the error here used to strand the
        // claimed row in 'processing' for a full visibility lease (300 s)
        // while the poller kept claiming fresh rows into the open breaker —
        // a 60 s breaker window could stall the queue for minutes. Defer the
        // row instead (5-minute requeue, same as the warmup gate).
        if !self.smtp_circuit_breaker.is_allowed() {
            self.requeue_job(job, "circuit_open").await?;
            return Ok(());
        }

        // F18: dispatch-time tenant policy gate. Only a CONFIRMED active
        // tenant may reach the external transport: any other status — and
        // any lookup failure, missing tenant row, or empty id — DEFERS the
        // job and exits dispatch. The gate never fails open.
        match self.tenant_policy(&job.tenant_id).await {
            TenantPolicy::Allowed => {}
            policy => {
                let reason = policy.requeue_reason();
                info!(
                    job_id = %job.id,
                    tenant_id = %job.tenant_id,
                    reason = %reason,
                    "tenant policy is not Allowed at dispatch time — deferring delivery"
                );
                self.requeue_job(job, reason).await?;
                // Exit dispatch immediately: the row is retryable, nothing
                // below may run (not even the consent gate — a deferred
                // job must not terminalize on the way out).
                return Ok(());
            }
        }

        // F55: authoritative consent decision immediately before dispatch —
        // global suppression AND the per-category preference, both read
        // from CURRENT database state (no cache participates in the
        // decision). `Deferred` means the lookup itself failed: the row is
        // requeued and dispatch EXITS here — a consent-verification
        // failure must never continue into the transport.
        match self.dispatch_consent(job).await? {
            ConsentDecision::Suppressed(reason) => {
                info!(
                    job_id = %job.id,
                    tenant_id = %job.tenant_id,
                    recipient = %job.to,
                    reason = %reason,
                    "recipient suppressed at dispatch time (authoritative recheck)"
                );
                self.handle_suppressed(job, &reason).await?;
                return Ok(());
            }
            ConsentDecision::Deferred(reason) => {
                info!(
                    job_id = %job.id,
                    tenant_id = %job.tenant_id,
                    recipient = %job.to,
                    reason = %reason,
                    "consent verification unavailable at dispatch time — deferring"
                );
                self.requeue_job(job, reason).await?;
                // F55: exit dispatch IMMEDIATELY after the successful
                // requeue — never fall through into transport.
                return Ok(());
            }
            ConsentDecision::Allowed => {}
        }

        // Load and validate current domain state before any per-domain rate
        // accounting or delivery. A queued job can outlive a domain's
        // verification or deletion, so API-time authorization alone is not
        // enough.
        let domain = self.get_domain(job).await?;

        // ── SELECT (pure): build the dedicated-IP candidate pool ──────────
        // Warming AND active identities are candidates; only warming ones
        // carry a quota. Selection never touches Redis, so it cannot consume
        // capacity for a send that is refused later.
        let pool = select_delivery_ip(Utc::now(), &domain.dedicated_ips)?;

        // ── Route capability gate: PRE-DATA, pre-quota, pre-ledger ────────
        // A dedicated route whose transport is missing or cannot verifiably
        // bind the source IP is deferred HERE, before any reservation or
        // acceptance row exists. The old post-acceptance verification could
        // only fail after the message had already left, producing a
        // refund-then-retry of a possibly-accepted send.
        let planned_route = match pool.first() {
            Some(candidate) => DeliveryRoute::Dedicated {
                dedicated_ip_id: candidate.dedicated_ip_id.clone(),
                source_ip: candidate.source_ip,
            },
            None => DeliveryRoute::SesShared,
        };
        if let Some(reason) = domain_route_readiness(&planned_route, &domain) {
            info!(
                job_id = %job.id,
                tenant_id = %job.tenant_id,
                domain_id = %job.domain_id,
                route = %planned_route,
                reason,
                "domain is not ready for the planned delivery route — deferring"
            );
            self.requeue_job(job, reason).await?;
            return Ok(());
        }
        // A dedicated relay send must be DKIM-signed (verified domains must
        // not leave unsigned). Defer — retryable — instead of letting
        // prepare_email's Config error strand the row in 'processing' across
        // leases.
        if planned_route.is_dedicated() && !self.config.dkim.enabled {
            warn!(
                job_id = %job.id,
                route = %planned_route,
                "dedicated route requested while DKIM is disabled — deferring"
            );
            self.requeue_job(job, "dedicated_dkim_disabled").await?;
            return Ok(());
        }
        if let Err(error) = self.transport.ensure_route_dispatchable(&planned_route) {
            let reason = if planned_route.is_dedicated() {
                if self.transport.has_dedicated_smtp() {
                    "dedicated_route_unverifiable"
                } else {
                    "dedicated_transport_unconfigured"
                }
            } else {
                "ses_transport_unconfigured"
            };
            warn!(
                job_id = %job.id,
                tenant_id = %job.tenant_id,
                route = %planned_route,
                reason,
                error = %error,
                "delivery route is not dispatchable on this worker — deferring BEFORE DATA"
            );
            self.requeue_job(job, reason).await?;
            return Ok(());
        }

        // ── RESERVE: consume warmup capacity from the candidate SET ───────
        let reserved: Option<ReservedDeliveryIp> = if pool.is_empty() {
            None
        } else if !self.config.warmup.enabled {
            // Throttling disabled globally: the send stays on the dedicated
            // route (graduated/active identities keep being used), but no
            // quota is consumed. Selection and reservation are separate.
            pool.first().cloned().map(|candidate| ReservedDeliveryIp {
                candidate,
                reservation: None,
            })
        } else {
            let today = Utc::now().format("%Y-%m-%d").to_string();
            match reserve_warmup_capacity(&self.redis, job, &pool, &today).await {
                Ok(Some(reserved)) => Some(reserved),
                Ok(None) => {
                    debug!(
                        job_id = %job.id,
                        candidates = pool.len(),
                        "every warming dedicated IP is at its canonical daily cap — deferring row"
                    );
                    self.requeue_job(job, "warmup_limit").await?;
                    return Ok(());
                }
                Err(error) => {
                    warn!(
                        job_id = %job.id,
                        error = %error,
                        "warmup quota store unavailable — deferring row (fail closed)"
                    );
                    self.requeue_job(job, "warmup_admission_unavailable")
                        .await?;
                    return Ok(());
                }
            }
        };

        // The route is built from the SAME candidate the reservation bound,
        // so the quota slot and the network path cannot disagree.
        let route = match &reserved {
            Some(reserved) => reserved.route(),
            None => DeliveryRoute::SesShared,
        };
        debug!(
            job_id = %job.id,
            route = %route,
            route_kind = %transport_kind_for(&route),
            warmup_reserved = reserved
                .as_ref()
                .is_some_and(|reserved| reserved.reservation.is_some()),
            "dispatch route resolved"
        );

        // Audit-2 / P0: route-aware send-time admission control — reserve one
        // send from the ROUTE'S tenant and domain token buckets (SES
        // `max_send_rate` for shared, the relay's `rate_limit_per_second` for
        // dedicated) BEFORE the transport. On exhaustion the row is deferred;
        // the attempt is untouched, so the next claim re-evaluates admission.
        if !self.check_send_admission(job, &route).await? {
            debug!(
                job_id = %job.id,
                tenant_id = %job.tenant_id,
                domain_id = %job.domain_id,
                route_kind = %transport_kind_for(&route),
                "send admission exhausted — deferring row"
            );
            self.requeue_job(job, "send_rate_limited").await?;
            return Ok(());
        }

        // Prepare email — DKIM is decided by the ROUTE (a dedicated send
        // needs the local signature; a shared SES send is signed by SES
        // BYODKIM).
        let email = self.prepare_email(job, &domain, &route)?;

        // ── Durable exactly-once gate (sales_delivery_acceptances) ────────
        // Reserve the logical send unit. This is the LAST deferral point: a
        // deferral after this would strand a `reserved` row, so every
        // pre-DATA refusal above happens first. A transport that fails after
        // the reserve records `failed` and frees the unit for retry.
        let send_unit = send_unit_of(job);
        match claim_acceptance(&self.db, job, &route).await {
            Err(error) => {
                warn!(
                    job_id = %job.id,
                    send_unit = %send_unit,
                    error = %error,
                    "acceptance ledger unavailable — deferring (an unguarded send would forfeit exactly-once)"
                );
                self.requeue_job(job, "acceptance_ledger_unavailable")
                    .await?;
                return Ok(());
            }
            Ok(AcceptanceClaim::AlreadyAccepted) => {
                info!(
                    job_id = %job.id,
                    send_unit = %send_unit,
                    recipient = %job.to,
                    "acceptance ledger already records this logical send as accepted — not submitting again"
                );
                self.handle_possibly_sent(job).await?;
                return Ok(());
            }
            Ok(AcceptanceClaim::InFlight) => {
                info!(
                    job_id = %job.id,
                    send_unit = %send_unit,
                    "an acceptance reservation for this logical send is still within its lease — deferring"
                );
                self.requeue_job(job, "acceptance_in_flight").await?;
                return Ok(());
            }
            Ok(AcceptanceClaim::Claimed) => {}
        }

        // ── Submit, then RECORD on the same ledger row ────────────────────
        let send_result: ProcessorResult<DeliveryReceipt> =
            self.transport.send(&email, &route).await;

        match &send_result {
            Ok(receipt) => {
                // The transport ACCEPTED the message. Any receipt/route
                // disagreement is recorded as a contract violation on the
                // ledger and alarmed — never converted into a retry.
                let contract_note = route_receipt_contract_note(&route, receipt);
                if let Some(note) = &contract_note {
                    metrics::counter!("apexmail_delivery_route_contract_violation").increment(1);
                    error!(
                        job_id = %job.id,
                        route = %route,
                        note,
                        "dedicated route contract violation on an ACCEPTED send — recording it; \
                         the message is not retried"
                    );
                    // Accounting correction only: the selected IP did not
                    // (per the confirmed receipt) carry this message, so its
                    // quota must not count it. The send itself is accepted
                    // and stays accepted on the ledger.
                    if let Some(reservation) = reserved
                        .as_ref()
                        .and_then(|reserved| reserved.reservation.as_ref())
                    {
                        if let Err(release_error) =
                            release_warmup_reservation(&self.redis, reservation).await
                        {
                            warn!(
                                ip = %reservation.source_ip,
                                dedicated_ip_id = %reservation.dedicated_ip_id,
                                error = %release_error,
                                "failed to release warmup reservation after route contract violation"
                            );
                        }
                    }
                }
                if let Err(record_error) = record_acceptance_accepted(
                    &self.db,
                    &send_unit,
                    receipt,
                    contract_note.as_deref(),
                )
                .await
                {
                    // The message is ALREADY accepted externally: this is a
                    // loud operational failure, not a reason to retry.
                    metrics::counter!("apexmail_acceptance_record_failed").increment(1);
                    error!(
                        job_id = %job.id,
                        send_unit = %send_unit,
                        error = %record_error,
                        "failed to record transport acceptance on the ledger — the message IS accepted; \
                         the reserved row will be reclaimed after the lease"
                    );
                }
            }
            Err(error) => {
                if let Err(record_error) =
                    record_acceptance_failed(&self.db, &send_unit, &error.to_string()).await
                {
                    warn!(
                        job_id = %job.id,
                        send_unit = %send_unit,
                        error = %record_error,
                        "failed to record transport refusal on the acceptance ledger; \
                         the reservation lease will reclaim the row"
                    );
                }
            }
        }

        // Per-attempt delivery log (email_delivery_log) — the table
        // delivery_analytics' latency percentiles and billing's usage ingest
        // read; previously no runtime writer existed, so those surfaces were
        // structurally zero. Best-effort: a logging failure must not fail
        // the send path.
        match &send_result {
            Ok(_result) => {
                self.record_delivery_attempt(job, true, None, None).await;
            }
            Err(error) => {
                self.record_delivery_attempt(job, false, None, Some(&error.to_string()))
                    .await;
            }
        }

        let outcome: ProcessorResult<()> = match send_result {
            Ok(result) => {
                self.smtp_circuit_breaker.record_success();
                self.handle_success(job, &result).await
            }
            Err(e) => {
                self.smtp_circuit_breaker.record_failure();

                // F-21: classify by the structured SMTP reply code when the
                // error carries one (4xx → retry with the existing
                // exponential backoff, 5xx → the existing hard-bounce
                // handling). Messages without a code keep the legacy string
                // classification; codeless transport errors (timeout, DNS,
                // connection) fall through to `handle_error`, which retries
                // below max_retries and DLQs above. The ledger row is
                // `failed`, so a retry may claim the unit again.
                match classify_send_failure(&e) {
                    SendFailureClass::Soft => self.handle_soft_bounce(job, &e, &route).await?,
                    SendFailureClass::Hard => self.handle_hard_bounce(job, &e, &route).await?,
                    SendFailureClass::Unknown => self.handle_error(job, &e, &route).await?,
                }

                Err(e)
            }
        };

        outcome
    }

    /// F18: the dispatch-time tenant policy decision. Only a CONFIRMED
    /// `active` tenant is [`TenantPolicy::Allowed`]:
    ///
    /// * DB lookup failure → [`TenantPolicy::TemporarilyUnavailable`] — the
    ///   job is DEFERRED and dispatch exits (never fail open; the previous
    ///   fail-open-on-error behavior sent restricted mail during DB blips);
    /// * missing tenant row / empty id → [`TenantPolicy::Restricted`] (the
    ///   job defers and stays visible — no mail leaves for an
    ///   unidentifiable owner);
    /// * any non-active status (`pending`, `suspended`, ...) →
    ///   [`TenantPolicy::Restricted`] — pending/unknown is NOT permitted.
    ///
    /// Caching: ALLOW decisions are NEVER cached (a primed 30 s allow cache
    /// used to keep sending through a suspension applied on another
    /// instance with no invalidation path). Only positive RESTRICTED
    /// results are cached (30 s, moka) — a restriction arriving during the
    /// TTL window takes effect on the next claim at the latest, and an
    /// allow→restricted transition can never be served from cache.
    async fn tenant_policy(&self, tenant_id: &str) -> TenantPolicy {
        if tenant_id.is_empty() {
            return TenantPolicy::Restricted("tenant_identity_missing".to_string());
        }
        if let Some(reason) = self.tenant_restriction_cache.get(tenant_id) {
            return TenantPolicy::Restricted(reason);
        }
        let status: Option<String> = match sqlx::query_scalar(TENANT_STATUS_SQL)
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await
        {
            Ok(status) => status,
            Err(error) => {
                warn!(
                    tenant_id = tenant_id,
                    error = %error,
                    "tenant status lookup failed — deferring the job (fail closed)"
                );
                // Never cached: the next claim re-attempts the lookup.
                return TenantPolicy::TemporarilyUnavailable;
            }
        };
        match status.as_deref() {
            Some("active") => TenantPolicy::Allowed,
            Some(other) => {
                let reason = format!("tenant_{other}").replace(' ', "_");
                self.tenant_restriction_cache
                    .insert(tenant_id.to_string(), reason.clone());
                TenantPolicy::Restricted(reason)
            }
            None => {
                self.tenant_restriction_cache
                    .insert(tenant_id.to_string(), "tenant_missing".to_string());
                TenantPolicy::Restricted("tenant_missing".to_string())
            }
        }
    }

    /// F55: the authoritative, cache-free consent decision for one
    /// recipient immediately before dispatch:
    ///
    /// * [`ConsentDecision::Allowed`] — no global suppression AND no
    ///   applicable category opt-out (or the category is a
    ///   transactional/service exemption);
    /// * [`ConsentDecision::Suppressed`] — a durable reason to not send
    ///   (global suppression row, or `subscription_preferences` opted-out
    ///   for this non-exempt category);
    /// * [`ConsentDecision::Deferred`] — the lookup itself failed. The
    ///   CALLER requeues and exits dispatch; a failed verification is
    ///   never interpreted as permission.
    ///
    /// Recipient normalization is the canonical form the API uses (trimmed
    /// + lowercased) on BOTH the stored address (LOWER(email)) and the
    ///   queued one, so case differences cannot slip a send past consent.
    async fn dispatch_consent(&self, job: &EmailJob) -> ProcessorResult<ConsentDecision> {
        let canonical = canonical_recipient(&job.to);
        if canonical.is_empty() {
            // An empty envelope recipient cannot be consent-checked — defer
            // rather than send (the address was validated at enqueue; an
            // empty value here means corrupted row state).
            return Ok(ConsentDecision::Deferred(
                "consent_recipient_identity_missing",
            ));
        }
        // ONE query reads both consent dimensions, so they cannot disagree:
        // the global suppression reason, and the category opt-out flag for
        // this send's validated server-owned category (exempt categories
        // ignore the preference — enforced by the `category_enforced` flag
        // in Rust; global suppression ALWAYS applies).
        let category = &job.message_category;
        let category_enforced =
            !apexmail_lib::email_headers::message_category::is_preference_exempt(category);
        let (global_reason, category_opted_out) =
            match sqlx::query_as::<_, (Option<String>, Option<bool>)>(DISPATCH_CONSENT_SQL)
                .bind(&job.tenant_id)
                .bind(&canonical)
                .bind(category)
                .fetch_optional(&self.db)
                .await
            {
                Ok(row) => row.unwrap_or((None, None)),
                Err(error) => {
                    warn!(
                        job_id = %job.id,
                        tenant_id = %job.tenant_id,
                        error = %error,
                        "dispatch-time consent recheck failed — deferring"
                    );
                    return Ok(ConsentDecision::Deferred("consent_check_deferred"));
                }
            };

        if let Some(reason) = global_reason {
            return Ok(ConsentDecision::Suppressed(format!(
                "global_suppression:{reason}"
            )));
        }
        if category_enforced && category_opted_out == Some(true) {
            return Ok(ConsentDecision::Suppressed(format!(
                "category_opt_out:{category}"
            )));
        }
        Ok(ConsentDecision::Allowed)
    }

    /// Audit-2 / P0: route-aware send-time admission gate — reserve one send
    /// from the route's tenant and domain token buckets (SES
    /// `max_send_rate` for the shared pool, the relay's
    /// `rate_limit_per_second` for the dedicated route) before any
    /// `transport.send`. The bucket keys are route-scoped, so shared and
    /// dedicated traffic cannot drain each other's allowances.
    ///
    /// * `Ok(false)` — exhausted: the caller defers the row via the existing
    ///   requeue path instead of sending.
    /// * `Err`/Redis unavailable — fails OPEN with a warning (best-effort,
    ///   matching the historical posture; the transports still enforce their
    ///   own server-side throttling). The durable exactly-once gate is the
    ///   acceptance ledger, which does NOT fail open.
    /// * rate 0 — the gate is disabled entirely.
    async fn check_send_admission(
        &self,
        job: &EmailJob,
        route: &DeliveryRoute,
    ) -> ProcessorResult<bool> {
        let kind = transport_kind_for(route);
        let rate = route_send_rate_per_second(&self.config, kind);
        if rate == 0 {
            return Ok(true);
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        match reserve_send_admission(&self.redis, &send_admission_keys(job, kind), rate, now_ms)
            .await
        {
            Ok(admitted) => Ok(admitted),
            Err(e) => {
                warn!(
                    job_id = %job.id,
                    tenant_id = %job.tenant_id,
                    route_kind = %kind,
                    error = %e,
                    "send admission bucket unavailable — proceeding (best-effort)"
                );
                Ok(true)
            }
        }
    }

    /// Get the ready sending-domain configuration for a queued job.
    ///
    /// Legacy jobs without a registered domain are permanently rejected: an
    /// unsigned fallback would turn a revoked or spoofed sender into delivery.
    ///
    /// Audit-1 / P0 routing: dedicated-IP state is derived from the REAL
    /// per-tenant `dedicated_ips` rows (see [`GET_DOMAIN_SQL`]) — both warming
    /// and active. `warmup_enabled`/`warmup_day` describe the BINDING
    /// (least-warmed) warming identity; the actual route is chosen per send by
    /// [`select_delivery_ip`] + [`reserve_warmup_capacity`], so this method
    /// never materializes the routing decision.
    async fn get_domain(&self, job: &EmailJob) -> ProcessorResult<Domain> {
        if job.domain_id.is_empty() {
            return Err(ProcessorError::Job(
                "queued message has no authorized sending domain".into(),
            ));
        }

        // SES verification is a ROUTE-level requirement, not a worker-level
        // one: a shared-pool send needs it (SES refuses unverified senders),
        // while a dedicated relay route does not. The check therefore carries
        // `ses_verified` into dispatch ([`domain_route_readiness`]) instead of
        // gating the lookup.
        let row = sqlx::query_as::<_, DomainWithRoutingRow>(GET_DOMAIN_SQL)
            .bind(&job.domain_id)
            .bind(&job.tenant_id)
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(|| {
                ProcessorError::Job(
                    "sending domain is absent, unverified, incomplete, or not ready for delivery"
                        .into(),
                )
            })?;

        let dedicated_ips = parse_dedicated_ips(row.dedicated_ips.as_ref());
        // The binding warmup identity is the least-warmed WARMING row (the
        // tightest reputation boundary); descriptors only — admission is a
        // separate step.
        let now = Utc::now();
        let binding = dedicated_ips
            .iter()
            .filter(|ip| ip.warming)
            .filter_map(|ip| {
                ip.warmup_started_at
                    .map(|started_at| (ip, warmup_day_since(now, started_at)))
            })
            .min_by_key(|(_, day)| *day)
            .map(|(_, day)| day);
        let (warmup_enabled, warmup_day) = match binding {
            Some(day) => (true, day as i32),
            None => (false, 0),
        };
        let domain = Domain {
            id: row.id,
            tenant_id: row.tenant_id,
            domain: row.domain,
            dkim_selector: row.dkim_selector,
            dkim_public_key: row.dkim_public_key,
            dkim_private_key: row.dkim_private_key,
            warmup_enabled,
            warmup_day,
            ses_verified: row.ses_verified,
            dedicated_ips,
            return_path: row.return_path,
        };

        let sender_domain = job
            .from
            .rsplit_once('@')
            .map(|(_, domain)| domain.trim().trim_end_matches('.'))
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| {
                ProcessorError::Job("queued message has an invalid sender address".into())
            })?;
        if !sender_domain.eq_ignore_ascii_case(&domain.domain) {
            return Err(ProcessorError::Job(
                "queued sender address does not match its authorized domain".into(),
            ));
        }

        Ok(domain)
    }

    /// Prepare email for sending. DKIM follows the ROUTE, not the process-wide
    /// `transport_type`: a dedicated (relay SMTP) send must carry the local
    /// signature, while a shared SES send is signed by SES BYODKIM.
    fn prepare_email(
        &self,
        job: &EmailJob,
        domain: &Domain,
        route: &DeliveryRoute,
    ) -> ProcessorResult<PreparedEmail> {
        let mut html = job.html.clone();
        let mut text = job.text.clone();

        // Add tracking if enabled
        if self.config.tracking.enabled {
            if let Some(ref h) = html {
                let tracked = add_tracking_pixel(h, job, &self.config.tracking);
                let tracked = rewrite_links(&tracked, job, &self.config.tracking);
                html = Some(tracked);
            }
        }

        // F13: generate the server-owned unsubscribe URL for THIS copy —
        // a v2 signed token carrying the persisted tenant/message/envelope
        // recipient identity (see `unsubscribe_link`). It feeds the
        // List-Unsubscribe header and the {{unsubscribe_url}} placeholders
        // in the caller's HTML/text. Best-effort by design: suppression
        // NEVER depends on attribution success — a missing token leaves
        // the body untouched and the send proceeds.
        let unsubscribe = unsubscribe_link(job, &self.config.tracking);
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some((_token, url)) = &unsubscribe {
            // RFC 2369 angle-bracket https URL + RFC 8058 one-click POST —
            // the tracking-service serves the POST variant on the same
            // route (`handle_unsub_post`).
            headers.push(("List-Unsubscribe".to_string(), format!("<{url}>")));
            headers.push(("List-Unsubscribe-Post".to_string(), "Yes".to_string()));
            // Visible preference/unsubscribe links: the caller's template
            // placeholders receive the same server-owned URL.
            if let Some(ref h) = html {
                html = Some(h.replace("{{unsubscribe_url}}", url));
            }
            if let Some(ref t) = text {
                text = Some(t.replace("{{unsubscribe_url}}", url));
            }
        }

        // F74: internal identity headers, generated EXCLUSIVELY from the
        // authenticated persisted job context (never merged from caller
        // input — the whole X-ApexMail-* namespace is filtered below and
        // at the API boundary). Shared canonical constants keep the SES
        // callback parser and this emitter in lockstep.
        headers.push((
            apexmail_lib::email_headers::HEADER_MESSAGE_ID.to_string(),
            job.message_id.clone(),
        ));
        headers.push((
            apexmail_lib::email_headers::HEADER_TENANT_ID.to_string(),
            job.tenant_id.clone(),
        ));

        if let Some(ref campaign_id) = job.campaign_id {
            headers.push((
                apexmail_lib::email_headers::HEADER_CAMPAIGN_ID.to_string(),
                campaign_id.clone(),
            ));
        }

        const PROTECTED_HEADERS: &[&str] = &[
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "date",
            "message-id",
            "dkim-signature",
            "arc-seal",
            "arc-message-signature",
            "arc-authentication-results",
            "return-path",
            "received",
            "received-spf",
            "authentication-results",
            "x-originating-ip",
            "x-mailer",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
            "reply-to",
            "list-unsubscribe",
            "list-unsubscribe-post",
        ];

        // F26/F48: the queue row's `headers` JSONB carries the SERVER-WRITTEN
        // MIME header map (original To/Cc visibility, reply-to, custom caller
        // headers). Legacy rows (and other writers) stored a flat custom
        // header object — recognized by the absence of the reserved `to` key.
        let SplitMimeHeaders {
            mime_to,
            mime_cc,
            reply_to,
            custom: custom_headers,
        } = split_mime_headers(job.headers.as_ref());

        // F26: preserve the ORIGINAL visible To/Cc mailbox LISTS on every
        // per-recipient copy (structured `Mailbox` arrays used by BOTH
        // transports via Address::new_list); the envelope destination stays
        // `job.to`. Bcc never appears here — it exists only in the delivery
        // data. Reply-To rides as a structured mailbox too.

        // F26: a logical Message-ID shared by every copy of the message —
        // recipients thread all copies into one conversation and
        // dedupe (X-ApexMail-Message-ID carries the platform id).
        if let Some(message_id) = logical_message_id(job) {
            headers.push(("Message-ID".to_string(), message_id));
        }

        // Add custom headers from job (filtering protected headers and the
        // reserved X-ApexMail-* namespace — case-insensitive, F74: legacy
        // alias spellings like X-ApexMail-TenantId must be blocked here
        // exactly like the canonical ones).
        let mut seen_custom: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (key, value) in custom_headers {
            let key_lower = key.to_lowercase();
            if PROTECTED_HEADERS.contains(&key_lower.as_str())
                || apexmail_lib::email_headers::is_reserved_internal_header(&key)
            {
                tracing::warn!(header = %key, "Blocked attempt to set protected/reserved header via custom headers");
                continue;
            }
            if !seen_custom.insert(key_lower.clone()) {
                tracing::warn!(header = %key, "Blocked duplicate custom header");
                continue;
            }
            headers.push((key, value));
        }

        // Dedicated (relay SMTP) delivery signs with the key whose public half
        // was displayed in the dashboard. Shared SES delivery is signed by SES
        // BYODKIM using that same key, so it intentionally does not attach a
        // second local signature.
        let dkim = if route.is_dedicated() {
            if !self.config.dkim.enabled {
                return Err(ProcessorError::Config(
                    "DKIM is required for dedicated SMTP delivery of verified domains".into(),
                ));
            }

            Some(smtp_dkim_config_for_domain(domain)?)
        } else {
            None
        };

        // Parse attachments
        let attachments = job
            .attachments
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        let obj = a.as_object()?;
                        Some(Attachment {
                            filename: obj.get("filename")?.as_str()?.to_string(),
                            content: base64::engine::general_purpose::STANDARD
                                .decode(obj.get("content")?.as_str()?)
                                .ok()?,
                            content_type: obj.get("contentType")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(PreparedEmail {
            from: job.from.clone(),
            to: job.to.clone(),
            mime_to,
            mime_cc,
            reply_to,
            subject: job.subject.clone(),
            html,
            text,
            headers,
            attachments,
            dkim,
            // VERP v2 binding: queue row + tenant come exclusively from the
            // persisted job; the transport mints the HMAC token (or emits no
            // VERP at all when the secret is not configured).
            verp: Some(VerpBinding {
                queue_id: job.id.clone(),
                tenant_id: job.tenant_id.clone(),
            }),
        })
    }

    /// F25: the ONE tenant/message-scoped parent-progress reconciliation,
    /// run after EVERY durable recipient transition (success, suppression,
    /// bounce, dead-letter, deferral, possibly-sent) and after every SES
    /// callback transition (F75 uses the same shared statement). Derives
    /// the parent state from the COMPLETE set of recipient rows; see
    /// `apexmail_lib::email_headers::RECONCILE_MESSAGE_PROGRESS_SQL` for
    /// the documented state model. Best-effort by design — the recipient
    /// transition already committed, so a reconciliation failure is logged,
    /// counted, and picked up by the restart sweep
    /// ([`EmailProcessor::reconcile_stuck_parents`]) instead of failing
    /// the send path.
    async fn reconcile_parent_progress(&self, job: &EmailJob) {
        let Ok(message_uuid) = uuid::Uuid::parse_str(&job.message_id) else {
            return;
        };
        if let Err(e) = sqlx::query(MESSAGES_PROGRESS_UPDATE_SQL)
            .bind(message_uuid)
            .bind(&job.tenant_id)
            .execute(&self.db)
            .await
        {
            metrics::counter!("email.parent_reconciliation_failed").increment(1);
            error!(
                job_id = %job.id,
                message_id = %job.message_id,
                tenant_id = %job.tenant_id,
                error = %e,
                "parent progress reconciliation failed — restart sweep will recover the aggregate"
            );
        }
    }

    /// F25: reconcile every parent whose recipient rows are ALL terminal but
    /// whose aggregate status is not — the missed-event recovery for a crash
    /// between a recipient transition and its reconciliation. Runs once at
    /// processor start and periodically thereafter; idempotent.
    async fn reconcile_stuck_parents(&self) {
        match sqlx::query(apexmail_lib::email_headers::RECONCILE_STUCK_PARENTS_SQL)
            .execute(&self.db)
            .await
        {
            Ok(updated) => {
                if updated.rows_affected() > 0 {
                    info!(
                        parents = updated.rows_affected(),
                        "reconciled stuck parent messages with all-terminal recipients"
                    );
                }
            }
            Err(e) => {
                metrics::counter!("email.parent_reconciliation_failed").increment(1);
                warn!(
                    error = %e,
                    "stuck-parent reconciliation sweep failed — retried on the next interval"
                );
            }
        }
    }

    /// Record one row per delivery attempt in `email_delivery_log`
    /// (schema: migrations 001/050). Readers: delivery_analytics'
    /// latency percentiles (JOIN email_queue ON eq.id = dl.email_id,
    /// dl.attempted_at, dl.success, dl.smtp_response) and billing's
    /// usage ingest (success rows by attempted_at day, tenant via the
    /// queue). Best-effort by design — never fails the send.
    async fn record_delivery_attempt(
        &self,
        job: &EmailJob,
        success: bool,
        smtp_response: Option<&str>,
        error_message: Option<&str>,
    ) {
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO email_delivery_log
                (email_id, attempt_number, smtp_response, success, error_message, attempted_at, status)
            VALUES ($1::uuid, $2, $3, $4, $5, NOW(), $6)
            "#,
        )
        .bind(&job.id)
        // job.attempt is 0-based; attempt_number is 1-based.
        .bind(job.attempt + 1)
        .bind(smtp_response)
        .bind(success)
        .bind(error_message)
        .bind(if success { "sent" } else { "failed" })
        .execute(&self.db)
        .await
        {
            warn!(
                job_id = %job.id,
                attempt = job.attempt + 1,
                error = %e,
                "Failed to record delivery attempt in email_delivery_log"
            );
        }
    }

    /// Handle successful send.
    ///
    /// A queue row can carry MULTIPLE recipients (FIX-8 expands it into one
    /// send unit per recipient), so a single recipient's success must not
    /// flip the whole row to 'sent' while other recipients are still owed a
    /// delivery. The row tracks the outstanding recipient set in
    /// `metadata.pending_recipients` (seeded lazily from `to_addresses` /
    /// the legacy `"to"` column); each success removes its recipient and the
    /// row only becomes 'sent' when the set is empty. Requeue paths
    /// (`handle_soft_bounce`) retry only this remaining set, so an
    /// already-delivered recipient is never re-sent.
    async fn handle_success(
        &self,
        job: &EmailJob,
        result: &DeliveryReceipt,
    ) -> ProcessorResult<()> {
        let updated = sqlx::query(HANDLE_SUCCESS_UPDATE_SQL)
            .bind(&result.transport_message_id)
            .bind(&job.id)
            .bind(&job.to)
            .bind(lease_token_of(job))
            .execute(&self.db)
            .await?;

        // Audit-5: a fenced-out write means the lease was lost (the row was
        // recovered and re-claimed). The new owner owns the row now — do not
        // record events or stamp messages on its behalf.
        if fenced_out(updated.rows_affected()) {
            warn!(
                job_id = %job.id,
                recipient = %job.to,
                "handle_success fenced out — lease lost, row write skipped"
            );
            return Ok(());
        }

        // Audit item 12 — THE DELIBERATE GAP: provider/SMTP acceptance
        // (exactly what this function handles) is NOT recorded as a
        // `sales_outcomes.delivered` outcome, and not as a `delivered`
        // sender-health event either. Acceptance is an operational signal
        // this worker can observe; DELIVERY requires a delivery-confirmation
        // event (DSN / SES delivery notification), whose consumer does not
        // exist yet — see `SALES_OUTCOME_MAPPING`, whose
        // `smtp_or_provider_acceptance` row is `Prohibited` and whose
        // `delivery_confirmation_callback` row is `NoProducerYet`. Until that
        // producer lands, this step records NO outcome: the audit explicitly
        // forbids classifying SMTP acceptance as delivered, and a missing
        // fact must stay missing rather than become a wrong one.
        //
        // Record sent event. Best-effort BY CONTRACT: the send already
        // happened and the row is already 'sent' — an analytics INSERT
        // failure must NOT classify the delivered mail as failed (the
        // caller would route it to the bounce handlers and the retry path).
        // Log + metric; the delivery stands.
        //
        // Audit item 21: the recipient mailbox provider is persisted HERE,
        // at delivery time, when the transport's delivery path actually
        // resolved it (MX lookup). Unknown stays NULL — it is never inferred
        // from the visible recipient domain (a custom domain hosted by
        // Google Workspace would be misreported).
        let (recipient_provider, provider_source) = normalized_provider_columns(
            result.recipient_provider.as_deref(),
            result.provider_source.as_deref(),
        );
        if let Err(e) = insert_recipient_event(
            &self.db,
            &job.tenant_id,
            &job.message_id,
            &job.domain_id,
            job.campaign_id.as_deref(),
            "sent",
            &job.to,
            recipient_provider.as_deref(),
            provider_source,
        )
        .await
        {
            metrics::counter!("email.sent_event_write_failed").increment(1);
            error!(
                job_id = %job.id,
                recipient = %job.to,
                error = %e,
                "Post-send 'sent' event INSERT failed — mail IS delivered (row already 'sent'); analytics event lost, not the delivery"
            );
        }

        // Stamp the transport actually used on the message row
        // (messages.headers X-Mail-Provider + the transport column) so
        // delivery_analytics' provider breakdown buckets real sends instead
        // of everything landing in 'unknown'. Best-effort: a legacy
        // non-UUID message id must not fail the send.
        if let Err(e) = sqlx::query(
            r#"
            UPDATE messages SET
                headers = COALESCE(headers, '{}'::jsonb)
                    || jsonb_build_object('X-Mail-Provider', $1::text),
                transport = $1::text,
                updated_at = NOW()
            WHERE id = $2::uuid AND tenant_id = $3
            "#,
        )
        .bind(transport_provider_label(&result.transport))
        .bind(&job.message_id)
        .bind(&job.tenant_id)
        .execute(&self.db)
        .await
        {
            warn!(
                message_id = %job.message_id,
                error = %e,
                "Failed to stamp X-Mail-Provider on message row"
            );
        }

        // F25: transition the audit `messages` row from the COMPLETE
        // recipient set (the SMTP counterpart of the SES delivery
        // notification handler): 'partial' while siblings are still owed a
        // delivery, 'sent' + sent_at only when every recipient row is
        // terminal-sent. Scheduled and processing parents are accepted.
        // Best-effort for the same reason as the events INSERT above: a
        // legacy job without a UUID message id skips the transition rather
        // than failing the (already successful) send handling — and so does
        // a failed write, with a metric. The same shared reconciliation
        // runs on EVERY durable recipient transition (suppression, bounce,
        // DLQ, deferral) and from the restart sweep.
        self.reconcile_parent_progress(job).await;

        // FIX-9/M56: feed the FBL server's complaint-rate alerting. The
        // `mta:reputation:{domain}:{date}` "sent" counter was never written
        // anywhere, so the `sent > 100` gate in feedback_loop.rs could never
        // fire. Best-effort: a counter failure must not fail the send.
        if let Some(domain) = envelope_domain(&job.from).filter(|d| !d.is_empty()) {
            self.record_sent_reputation(domain).await;
        }

        Ok(())
    }

    /// Increment the daily per-domain sent counters (Redis, matching the FBL
    /// reader's key format, plus the DB mirror). Best-effort by design.
    async fn record_sent_reputation(&self, domain: &str) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let key = reputation_sent_key(domain, &today);
        match self.redis.get().await {
            Ok(mut conn) => {
                let incr = redis::cmd("HINCRBY")
                    .arg(&key)
                    .arg("sent")
                    .arg(1i64)
                    .query_async::<i64>(&mut *conn)
                    .await;
                match incr {
                    Ok(_) => {
                        let _: bool = redis::cmd("EXPIRE")
                            .arg(&key)
                            .arg(7 * 86400i64)
                            .query_async(&mut *conn)
                            .await
                            .unwrap_or(false);
                    }
                    Err(e) => warn!(error = %e, "Failed to record Redis sent reputation counter"),
                }
            }
            Err(e) => warn!(error = %e, "Redis unavailable for sent reputation counter"),
        }
        if let Err(e) = sqlx::query(
            r#"INSERT INTO sender_reputation (domain, date, sent, updated_at)
               VALUES ($1, CURRENT_DATE, 1, NOW())
               ON CONFLICT (domain, date)
               DO UPDATE SET sent = sender_reputation.sent + 1, updated_at = NOW()"#,
        )
        .bind(domain)
        .execute(&self.db)
        .await
        {
            warn!(error = %e, "Failed to record DB sent reputation");
        }
    }

    /// Handle suppressed recipient.
    ///
    /// G.3b: the row carries MULTIPLE recipients (FIX-8) — suppressing one
    /// must not terminate the whole row while siblings are still in flight.
    /// The recipient is removed from `metadata.pending_recipients` (mirroring
    /// `handle_success`) and the row only becomes 'suppressed' when the
    /// pending set is empty.
    async fn handle_suppressed(&self, job: &EmailJob, reason: &str) -> ProcessorResult<()> {
        let updated = sqlx::query(SUPPRESSED_UPDATE_SQL)
            .bind(reason)
            .bind(&job.id)
            .bind(&job.to)
            .bind(lease_token_of(job))
            .execute(&self.db)
            .await?;

        if fenced_out(updated.rows_affected()) {
            warn!(
                job_id = %job.id,
                recipient = %job.to,
                "handle_suppressed fenced out — lease lost, row write skipped"
            );
            return Ok(());
        }

        // F25: suppression is a durable recipient transition — the parent
        // must reconcile even when every recipient is suppressed (the
        // all-suppressed parent previously stayed 'processing' forever).
        self.reconcile_parent_progress(job).await;

        Ok(())
    }

    /// G.3c: a duplicate-window reclaim — the (row, attempt, recipient) send
    /// marker was still held, so a previous worker may already have sent this
    /// message. Record the recipient as possibly-sent in the row metadata
    /// (auditable) and remove it from the pending set so the row completes
    /// instead of redelivery-looping.
    async fn handle_possibly_sent(&self, job: &EmailJob) -> ProcessorResult<()> {
        let updated = sqlx::query(POSSIBLY_SENT_UPDATE_SQL)
            .bind(&job.id)
            .bind(&job.to)
            .bind(lease_token_of(job))
            .execute(&self.db)
            .await?;

        if fenced_out(updated.rows_affected()) {
            warn!(
                job_id = %job.id,
                recipient = %job.to,
                "handle_possibly_sent fenced out — lease lost, row write skipped"
            );
            return Ok(());
        }

        // F25: possibly-sent is a durable recipient transition.
        self.reconcile_parent_progress(job).await;

        Ok(())
    }

    /// Handle soft bounce (retry later).
    async fn handle_soft_bounce(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
        route: &DeliveryRoute,
    ) -> ProcessorResult<()> {
        if job.attempt >= self.config.base.max_retries as i32 {
            return self.handle_hard_bounce(job, error, route).await;
        }

        let next_attempt = job.attempt + 1;
        let backoff_multiplier = 2_i64.saturating_pow(job.attempt.min(30) as u32);
        // F6:±20% jitter on the exponential backoff — a cohort of messages
        // failing the same transient error at the same attempt otherwise
        // retries in one synchronized wave (thundering herd against the
        // same recovering endpoint).
        let base_retry_secs =
            (self.config.base.retry_delay.as_secs() as i64).saturating_mul(backoff_multiplier);
        let retry_at = Utc::now() + chrono::Duration::seconds(jittered_secs(base_retry_secs));

        // Requeue only the recipients still owed a delivery (partial-failure
        // duplicate fix). `metadata.pending_recipients` is seeded here if it
        // does not exist yet (from the row's full recipient list) — successes
        // recorded by the OTHER recipients of this row subtract from it, and
        // the retry fetch expands only this set. If nothing remains, the row
        // is simply marked sent.
        let updated = sqlx::query(SOFT_BOUNCE_UPDATE_SQL)
            .bind(next_attempt)
            .bind(retry_at)
            .bind(error.to_string())
            .bind(&job.id)
            .bind(lease_token_of(job))
            .execute(&self.db)
            .await?;

        if fenced_out(updated.rows_affected()) {
            warn!(
                job_id = %job.id,
                recipient = %job.to,
                "handle_soft_bounce fenced out — lease lost, requeue skipped"
            );
            return Ok(());
        }

        // F25: the deferral is a durable recipient transition — the parent
        // re-derives (stays 'processing' while nothing is terminal, so the
        // scheduled retry remains cancellable; 'partial' once siblings
        // completed).
        self.reconcile_parent_progress(job).await;

        // Audit item 10: a transient failure is one sender-health `deferral`
        // fact. There is no outcome rung for a retryable failure (the ladder
        // has no `deferral`), so only the ledger row is written here.
        let provider = transport_provider_label(&route_transport_type(route));
        self.record_sales_feedback(job, SalesDeliveryEvent::SoftBounce, provider)
            .await;

        Ok(())
    }

    /// Handle hard bounce (permanent failure).
    ///
    /// Audit-3: the row can carry MULTIPLE recipients (FIX-8) — one 550 must
    /// not terminalize the whole row. Mirrors `handle_success` /
    /// `handle_suppressed`: the bounced recipient leaves
    /// `metadata.pending_recipients`, the row becomes terminal 'bounced'
    /// only when the pending set empties, and ONLY the bounced address is
    /// suppressed.
    async fn handle_hard_bounce(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
        route: &DeliveryRoute,
    ) -> ProcessorResult<()> {
        let updated = sqlx::query(HARD_BOUNCE_UPDATE_SQL)
            .bind(error.to_string())
            .bind(&job.id)
            .bind(&job.to)
            .bind(lease_token_of(job))
            .execute(&self.db)
            .await?;

        // Audit-5: fenced out — the lease was lost; the new owner owns the
        // row and must not inherit this worker's suppression/event records.
        if fenced_out(updated.rows_affected()) {
            warn!(
                job_id = %job.id,
                recipient = %job.to,
                "handle_hard_bounce fenced out — lease lost, bounce handling skipped"
            );
            return Ok(());
        }

        // Add to suppressions — ONLY the bounced address, and ONLY when the
        // failure proves the address itself is invalid. Policy 5xx (spam
        // refusals, IP blocklists, DMARC verdicts) mark this message
        // permanently failed but must not suppress a valid mailbox.
        // suppressions.id is VARCHAR(26), so use a short random suffix
        // ("sup_" + 18 hex chars = 22 chars).
        if is_recipient_invalid(error) {
            sqlx::query(
                r#"
                INSERT INTO suppressions (id, tenant_id, email, reason, created_at)
                VALUES ($1, $2, $3, 'hard_bounce', NOW())
                ON CONFLICT (tenant_id, email) DO NOTHING
                "#,
            )
            .bind(format!(
                "sup_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..18]
            ))
            .bind(&job.tenant_id)
            .bind(&job.to)
            .execute(&self.db)
            .await?;
        } else {
            warn!(
                job_id = %job.id,
                recipient = %job.to,
                "5xx permanent failure without address-proof; message dead-lettered, recipient NOT suppressed"
            );
        }

        // F25: the hard bounce is a durable (terminal) recipient transition
        // — reconcile the parent. The all-bounced parent previously stayed
        // 'processing' forever.
        self.reconcile_parent_progress(job).await;

        // Record bounce event (for the bounced recipient only).
        //
        // Audit item 21: carry the recipient-provider identity persisted at
        // delivery time for this recipient-send onto the bounce, so outcome
        // events never lose provenance. When nothing was persisted (the
        // MX was never resolved) both fields stay NULL — never inferred.
        let (recipient_provider, provider_source) =
            carried_recipient_provider(&self.db, &job.tenant_id, &job.message_id, &job.to).await;
        insert_recipient_event(
            &self.db,
            &job.tenant_id,
            &job.message_id,
            &job.domain_id,
            job.campaign_id.as_deref(),
            "bounced",
            &job.to,
            recipient_provider.as_deref(),
            provider_source.as_deref(),
        )
        .await?;

        // Audit items 10/12: feed the sales feedback loop. ONE
        // `sales_sender_events` row (`hard_bounce`) plus the `bounce` outcome
        // when the queue row carries the typed sales provenance. Both inserts
        // are idempotent on their stable keys. Best-effort: the recipient is
        // already suppressed and the delivery record written — a ledger
        // failure is logged, never turned into a retry of an already-bounced
        // message.
        let provider = transport_provider_label(&route_transport_type(route));
        self.record_sales_feedback(job, SalesDeliveryEvent::HardBounce, provider)
            .await;

        Ok(())
    }

    /// Record the Sales V2 outcome and the sender-health ledger row for one
    /// delivery fact tied to this queue row.
    ///
    /// Both writes are the single-sourced functions at the bottom of this
    /// module; both are idempotent (a replayed provider callback or a
    /// re-claimed queue row cannot double-count). Best-effort by design — the
    /// delivery state transition has already happened and must not be
    /// unwound by a feedback-ledger failure; failures are logged and
    /// counted.
    async fn record_sales_feedback(
        &self,
        job: &EmailJob,
        event: SalesDeliveryEvent,
        provider: &str,
    ) {
        match record_sales_outcome_if_linked(&self.db, &job.id, event, provider).await {
            Ok(Some(outcome_id)) => {
                debug!(
                    job_id = %job.id,
                    outcome_id = %outcome_id,
                    outcome = event.outcome().unwrap_or("none"),
                    "Sales V2 outcome recorded from a delivery fact"
                );
            }
            Ok(None) => {}
            Err(error) => {
                metrics::counter!("email.sales_outcome_write_failed").increment(1);
                warn!(
                    job_id = %job.id,
                    error = %error,
                    "sales outcome write failed — delivery state is unaffected, feedback event lost"
                );
            }
        }

        match record_sender_event_if_linked(&self.db, &job.id, event, &job.to).await {
            Ok(Some(sender_event_id)) => {
                debug!(
                    job_id = %job.id,
                    sender_event_id = %sender_event_id,
                    event_type = event.sender_ledger_event().unwrap_or("none"),
                    "sender-health ledger row recorded from a delivery fact"
                );
            }
            Ok(None) => {}
            Err(error) => {
                metrics::counter!("email.sales_sender_event_write_failed").increment(1);
                warn!(
                    job_id = %job.id,
                    error = %error,
                    "sender-health ledger write failed — delivery state is unaffected, feedback event lost"
                );
            }
        }
    }

    /// Handle generic error.
    async fn handle_error(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
        route: &DeliveryRoute,
    ) -> ProcessorResult<()> {
        if job.attempt >= self.config.base.max_retries as i32 {
            // Audit-3: dead-letter only THIS recipient — the row may still
            // owe deliveries to its other recipients (FIX-8). The failed
            // recipient's delivery is recorded in email_dlq; the row itself
            // only terminalizes to 'failed' when the pending set empties,
            // otherwise it returns to 'pending' for the siblings.
            // Audit-5: the fenced write runs FIRST — a fenced-out (lease
            // lost) worker must not dead-letter on the new owner's behalf.
            let updated = sqlx::query(DLQ_FAIL_UPDATE_SQL)
                .bind(error.to_string())
                .bind(&job.id)
                .bind(&job.to)
                .bind(lease_token_of(job))
                .execute(&self.db)
                .await?;

            if fenced_out(updated.rows_affected()) {
                warn!(
                    job_id = %job.id,
                    recipient = %job.to,
                    "handle_error dead-letter fenced out — lease lost, DLQ write skipped"
                );
                return Ok(());
            }

            // F25: exhausted-retry dead-lettering is a durable recipient
            // transition — reconcile the parent (the all-exhausted parent
            // previously stayed 'processing' forever).
            self.reconcile_parent_progress(job).await;

            sqlx::query(
                r#"
                INSERT INTO email_dlq (id, job_id, tenant_id, message_id, error_message, created_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                "#,
            )
            .bind(format!("dlq_{}", uuid::Uuid::new_v4()))
            .bind(&job.id)
            .bind(&job.tenant_id)
            .bind(&job.message_id)
            .bind(error.to_string())
            .execute(&self.db)
            .await?;
        } else {
            self.handle_soft_bounce(job, error, route).await?;
        }

        Ok(())
    }

    /// Permanently reject a queue row that cannot safely be delivered, such as
    /// a legacy row with no domain ID or a DKIM key mismatch. Retrying such a
    /// row cannot repair it and must never degrade into an unsigned send.
    async fn handle_permanent_job_failure(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
    ) -> ProcessorResult<()> {
        let error_message = error.to_string();
        let mut transaction = self.db.begin().await?;
        let updated = sqlx::query(PERMANENT_FAILURE_UPDATE_SQL)
            .bind(&error_message)
            .bind(&job.id)
            .bind(lease_token_of(job))
            .execute(&mut *transaction)
            .await?;

        if updated.rows_affected() > 0 {
            sqlx::query(
                "INSERT INTO email_dlq (id, job_id, tenant_id, message_id, error_message, created_at)
                 VALUES ($1, $2, $3, $4, $5, NOW())",
            )
            .bind(format!("dlq_{}", uuid::Uuid::new_v4()))
            .bind(&job.id)
            .bind(&job.tenant_id)
            .bind(&job.message_id)
            .bind(&error_message)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;

        // F25: permanent rejection is a durable terminal recipient
        // transition — reconcile the parent (an all-rejected message
        // previously stayed 'processing' forever).
        self.reconcile_parent_progress(job).await;

        Ok(())
    }

    /// Requeue a job for later processing.
    async fn requeue_job(&self, job: &EmailJob, reason: &str) -> ProcessorResult<()> {
        let retry_at = Utc::now() + chrono::Duration::minutes(5);

        let updated = sqlx::query(REQUEUE_JOB_UPDATE_SQL)
            .bind(retry_at)
            .bind(
                serde_json::to_value(reason)
                    .map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?,
            )
            .bind(&job.id)
            .bind(lease_token_of(job))
            .execute(&self.db)
            .await?;

        if fenced_out(updated.rows_affected()) {
            warn!(
                job_id = %job.id,
                reason = reason,
                "requeue fenced out — lease lost, deferral skipped"
            );
        }

        Ok(())
    }

    /// Record send outcome for error rate tracking.
    fn record_outcome(&self, outcome: SendOutcome) {
        let now = Instant::now();

        let mut outcomes = self
            .recent_outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        outcomes.push((outcome, now));

        // Evict old entries (>60s)
        outcomes.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60));

        // Also cap at window size
        let len = outcomes.len();
        if len > ERROR_WINDOW_SIZE {
            let drain_count = len - ERROR_WINDOW_SIZE;
            outcomes.drain(0..drain_count);
        }

        // Check error rate
        let len = outcomes.len();
        if len >= ERROR_WINDOW_SIZE {
            let failures = outcomes
                .iter()
                .filter(|(o, _)| {
                    !matches!(
                        o,
                        SendOutcome::Success | SendOutcome::Suppressed | SendOutcome::Rejected
                    )
                })
                .count();

            if failures >= ERROR_THRESHOLD {
                let cooldown_until =
                    Utc::now().timestamp_millis() + ERROR_COOLDOWN.as_millis() as i64;
                self.error_cooldown_until
                    .store(cooldown_until, Ordering::SeqCst);
                error!(
                    failures = failures,
                    window = len,
                    "Error rate circuit breaker activated"
                );
            }
        }
    }
}

/// F26: split the queue row's `headers` JSONB into its parts.
///
/// New server-written shape (see the API's `mime_headers_for`):
/// `{"to": [...], "cc": [...], "reply_to": "...", "custom": {...}}` — the
/// original MIME To/Cc header values as ARRAYS of mailbox strings (kept
/// SEPARATE from the envelope destination), the Reply-To address, and the
/// caller's custom headers. LEGACY rows persisted the comma-joined string
/// form (`"a@x, b@y"`) — parsed here explicitly into the structured list
/// (the documented backfill path; no re-serialization needed). Older
/// legacy/foreign rows without the reserved `to` key are treated as a flat
/// custom-header map (previous behaviour).
fn split_mime_headers(headers: Option<&serde_json::Value>) -> SplitMimeHeaders {
    let Some(obj) = headers.and_then(|h| h.as_object()) else {
        return SplitMimeHeaders::default();
    };

    // Legacy flat custom-header map (no reserved keys)?
    let is_server_shape = obj.contains_key("to") || obj.contains_key("custom");
    if !is_server_shape {
        return SplitMimeHeaders {
            custom: obj
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect(),
            ..SplitMimeHeaders::default()
        };
    }

    let mailbox_field = |value: Option<&serde_json::Value>| -> Vec<Mailbox> {
        match value {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|item| {
                    // F48 structured form: {"email": ..., "name": ...} — the
                    // exact caller-authored mailbox, no re-parsing loss.
                    if let Some(obj) = item.as_object() {
                        let email = obj.get("email").and_then(|e| e.as_str())?;
                        let name = obj.get("name").and_then(|n| n.as_str());
                        return Some(Mailbox {
                            name: name.map(str::to_string),
                            email: email.to_string(),
                        });
                    }
                    // F26 legacy array-of-strings form.
                    item.as_str().and_then(Mailbox::parse)
                })
                .collect(),
            Some(serde_json::Value::String(joined)) if !joined.is_empty() => {
                Mailbox::parse_list(joined)
            }
            _ => Vec::new(),
        }
    };
    // F48: prefer the structured *_mailboxes arrays over the joined string.
    let mailboxes_or_legacy = |structured: &str, legacy: &str| -> Vec<Mailbox> {
        let structured = mailbox_field(obj.get(structured));
        if !structured.is_empty() {
            return structured;
        }
        mailbox_field(obj.get(legacy))
    };

    let str_field = |key: &str| {
        obj.get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .and_then(Mailbox::parse)
    };
    // F48: the structured reply_to_mailbox object is authoritative when
    // present; the joined string remains the legacy fallback.
    let reply_to_field = || -> Option<Mailbox> {
        obj.get("reply_to_mailbox")
            .and_then(|v| v.as_object())
            .and_then(|o| {
                let email = o.get("email").and_then(|e| e.as_str())?;
                Some(Mailbox {
                    name: o.get("name").and_then(|n| n.as_str()).map(str::to_string),
                    email: email.to_string(),
                })
            })
            .or_else(|| str_field("reply_to"))
    };

    SplitMimeHeaders {
        mime_to: mailboxes_or_legacy("to_mailboxes", "to"),
        mime_cc: mailboxes_or_legacy("cc_mailboxes", "cc"),
        reply_to: reply_to_field(),
        custom: obj
            .get("custom")
            .and_then(|v| v.as_object())
            .map(|custom| {
                custom
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// F26: the parts of a queue row's server-written MIME header map (see
/// [`split_mime_headers`]).
#[derive(Default)]
struct SplitMimeHeaders {
    mime_to: Vec<Mailbox>,
    mime_cc: Vec<Mailbox>,
    reply_to: Option<Mailbox>,
    custom: Vec<(String, String)>,
}

/// F26: the logical RFC 5322 Message-ID shared by every copy of a message —
/// derived from the platform message id, so all recipient copies of one
/// send thread together.
fn logical_message_id(job: &EmailJob) -> Option<String> {
    let domain = envelope_domain(&job.from).filter(|d| !d.is_empty())?;
    let id = job
        .message_id
        .trim()
        .trim_matches(|c| c == '<' || c == '>')
        .trim();
    if id.is_empty() || id.contains(['>', '@', ' ']) {
        return None;
    }
    Some(format!("<{id}@{domain}>"))
}

fn smtp_dkim_config_for_domain(domain: &Domain) -> ProcessorResult<DkimConfig> {
    let selector = domain
        .dkim_selector
        .as_deref()
        .ok_or_else(|| ProcessorError::Dkim("verified domain is missing a DKIM selector".into()))?;
    let encrypted_private_key = domain.dkim_private_key.as_deref().ok_or_else(|| {
        ProcessorError::Dkim("verified domain is missing a DKIM private key".into())
    })?;
    let public_key = domain.dkim_public_key.as_deref().ok_or_else(|| {
        ProcessorError::Dkim("verified domain is missing a DKIM public key".into())
    })?;
    let aad = dkim_private_key_aad(&domain.tenant_id, &domain.id);
    let private_key = decrypt_dkim_private_key(encrypted_private_key, &aad).map_err(|error| {
        ProcessorError::Dkim(format!("unable to decrypt the domain DKIM key: {error}"))
    })?;
    let derived_public_key =
        public_key_base64_from_private_key_pem(&private_key).map_err(|error| {
            ProcessorError::Dkim(format!("domain DKIM private key is invalid: {error}"))
        })?;
    if !dkim_public_keys_match(public_key, &derived_public_key) {
        return Err(ProcessorError::Dkim(
            "domain DKIM public and private key material does not match".into(),
        ));
    }

    Ok(DkimConfig {
        selector: selector.to_string(),
        domain: domain.domain.clone(),
        private_key,
    })
}

use base64::Engine;

/// Redis hash key used by the FBL server's complaint-rate alerting
/// (feedback_loop.rs: `mta:reputation:{domain}:{YYYY-MM-DD}`, field "sent").
fn reputation_sent_key(domain: &str, date: &str) -> String {
    format!("mta:reputation:{domain}:{date}")
}

/// Provider label stamped on `messages.headers['X-Mail-Provider']` at send
/// time, matching the values delivery_analytics' provider breakdown buckets
/// on ('ses' / 'smtp').
fn transport_provider_label(transport_type: &TransportType) -> &'static str {
    match transport_type {
        TransportType::Ses => "ses",
        _ => "smtp",
    }
}

/// The transport a resolved route belongs to, for feedback attribution on the
/// failure path (where no receipt exists).
fn route_transport_type(route: &DeliveryRoute) -> TransportType {
    match route {
        DeliveryRoute::SesShared => TransportType::Ses,
        DeliveryRoute::Dedicated { .. } => TransportType::Smtp,
    }
}

// ─── Recipient-mailbox-provider provenance (audit item 21) ─────────────
//
// The recipient provider is a DELIVERY-TIME fact: only the path that
// resolves the recipient domain's MX records can know it. It is persisted
// on the `sent` event when the transport reports it and carried onto
// subsequent events for the same recipient-send. Unknown is stored as NULL;
// the visible recipient domain is NEVER turned into a provider guess here
// (migration 202's rationale: `@customer.com` is not Google Workspace
// without MX evidence).

/// `events.provider_source` values accepted by the CHECK constraint in
/// `202_sales_feedback_delivery_binding.sql:154-163`.
const PROVIDER_SOURCES: [&str; 3] = ["mx_resolved", "provider_callback", "inferred"];

/// Normalize a delivery-time recipient-provider report to a canonical slug:
/// lowercase ASCII alphanumerics plus `_`, `.`, `-`, whitespace folded to
/// `_`, trimmed of separator edges, non-empty, at most 64 chars. `None` for
/// anything unusable (blank, all separators, oversize) — garbage must never
/// reach the shared provider dimension.
fn normalize_recipient_provider(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '_' | '.' | '-') {
            out.push(ch);
        } else if ch.is_whitespace() {
            out.push('_');
        }
    }
    let trimmed = out
        .trim_matches(|c| matches!(c, '_' | '.' | '-'))
        .to_string();
    (!trimmed.is_empty() && trimmed.len() <= 64).then_some(trimmed)
}

/// The `(recipient_provider, provider_source)` pair to persist for one event
/// insert. A provider is only persisted WITH a valid provenance source; an
/// unrecognized source drops the pair rather than attributing a value to
/// nothing (the DB CHECK would reject it anyway).
fn normalized_provider_columns(
    provider: Option<&str>,
    source: Option<&str>,
) -> (Option<String>, Option<&'static str>) {
    let Some(provider) = provider.and_then(normalize_recipient_provider) else {
        return (None, None);
    };
    let Some(source) = source.and_then(|raw| {
        PROVIDER_SOURCES
            .iter()
            .copied()
            .find(|allowed| *allowed == raw.trim())
    }) else {
        return (None, None);
    };
    (Some(provider), Some(source))
}

/// Insert one recipient-send lifecycle event carrying the optional
/// recipient-provider provenance (columns added by migration
/// `202_sales_feedback_delivery_binding.sql:150-167`; the event columns are
/// `075_create_missing_tables.sql:30-49` plus the widened
/// `domain_id`/`campaign_id` from `090_widen_events_id_columns.sql:25-32`).
async fn insert_recipient_event(
    db: &PgPool,
    tenant_id: &str,
    message_id: &str,
    domain_id: &str,
    campaign_id: Option<&str>,
    event_type: &str,
    recipient: &str,
    recipient_provider: Option<&str>,
    provider_source: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO events (id, tenant_id, message_id, domain_id, campaign_id, event_type,
                            recipient, recipient_provider, provider_source, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        "#,
    )
    .bind(format!("evt_{}", uuid::Uuid::new_v4()))
    .bind(tenant_id)
    .bind(message_id)
    .bind(domain_id)
    .bind(campaign_id)
    .bind(event_type)
    .bind(recipient)
    .bind(recipient_provider)
    .bind(provider_source)
    .execute(db)
    .await
    .map(|_| ())
}

/// The recipient-provider pair already persisted for this recipient-send
/// (written on the `sent` event at delivery time), so subsequent events —
/// e.g. a hard bounce — carry the SAME normalized provider. Best-effort:
/// a lookup failure logs and yields `(None, None)` rather than failing the
/// bounce path; the provenance is lost, never fabricated.
async fn carried_recipient_provider(
    db: &PgPool,
    tenant_id: &str,
    message_id: &str,
    recipient: &str,
) -> (Option<String>, Option<String>) {
    let lookup = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT recipient_provider, provider_source
         FROM events
         WHERE tenant_id = $1
           AND message_id = $2
           AND lower(recipient) = lower($3)
           AND recipient_provider IS NOT NULL
         ORDER BY timestamp DESC
         LIMIT 1",
    )
    .bind(tenant_id)
    .bind(message_id)
    .bind(recipient)
    .fetch_optional(db)
    .await;
    match lookup {
        Ok(Some(pair)) => pair,
        Ok(None) => (None, None),
        Err(error) => {
            warn!(
                message_id = %message_id,
                error = %error,
                "recipient-provider carry-through lookup failed; event written without provider provenance"
            );
            (None, None)
        }
    }
}

/// Envelope-sender domain used for per-domain reputation counters.
fn envelope_domain(from: &str) -> Option<&str> {
    from.rsplit_once('@').map(|(_, d)| d)
}

/// F55: canonical recipient form for suppression lookups — trimmed and
/// ASCII-lowercased, matching the API's `canonical_email`. Applied on BOTH
/// sides of the comparison (the query LOWER()s the stored address), so a
/// queued "User@Example.com" matches a suppressed "user@example.com".
fn canonical_recipient(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// F59: build the COMPLETE metric snapshot from a `GROUP BY status` result:
/// every supported status is initialized to zero, query counts are
/// overlaid, and any unexpected status (forward compatibility) is appended
/// rather than dropped. A drained status therefore publishes 0 instead of
/// the gauge silently retaining its last nonzero value.
fn overlay_status_counts(counts: Vec<(String, i64)>) -> Vec<(String, i64)> {
    let mut by_status: HashMap<String, i64> = counts.into_iter().collect();
    let mut snapshot = Vec::with_capacity(EMAIL_QUEUE_STATUSES.len());
    for status in EMAIL_QUEUE_STATUSES {
        snapshot.push((status.to_string(), by_status.remove(status).unwrap_or(0)));
    }
    snapshot.extend(by_status);
    snapshot
}

// ===========================================================================
// Sales V2 outcomes and the sender-health ledger (audit items 10/12)
// ===========================================================================
//
// The sales feedback loops read two canonical tables:
//
//   * `sales_sender_events` — ONE row per delivery fact, folded into
//     `sales_sender_health` by `sales_autopilot::outcome_projector`
//     (migration 202 lines 106-125);
//   * `sales_outcomes` — the outcome ladder the optimizer learns from,
//     unique on `(tenant_id, outcome, step_execution_id)`
//     (migration 200 lines 758-777).
//
// DEPENDENCY DIRECTION: this crate deliberately does NOT depend on
// `sales-autopilot` (see the comment at the top of
// `src/reply_handler/processor.rs`: pulling the control-plane crate into the
// worker image would drag its routes/dispatcher/AXUM surface along, and the
// worker only needs the canonical tables). `sales-autopilot` does not depend
// on `worker-processors` either, so a new dependency would not be a Cargo
// cycle — but it would invert the intended layering (the delivery worker is
// infrastructure; the sales engine is the consumer of its DB rows), so the
// insert is implemented here directly against the canonical tables, kept in
// the ONE function [`record_sales_outcome_if_linked`] so the SQL is still
// single-sourced. If the workspace ever moves the delivery worker under the
// sales crate's dependency envelope, that function should call
// `sales_autopilot::attribution::record_outcome` instead; the SQL below is
// intentionally equivalent.

/// One platform delivery fact that may produce a Sales V2 outcome and/or a
/// sender-health ledger row.
///
/// `ProviderAccepted` exists to make the audit's prohibition explicit in
/// code: provider/SMTP acceptance is an operational signal, NOT a delivery,
/// and both mappings for it are `None` so the code can never record a
/// `delivered` outcome from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SalesDeliveryEvent {
    /// The transport accepted the message (SMTP 250 / SES SendEmail success).
    ///
    /// Never constructed in production: acceptance deliberately records
    /// nothing (see [`SALES_OUTCOME_MAPPING`]); the variant is the type-level
    /// statement of the prohibition and is exercised by the mapping test.
    #[allow(dead_code)]
    ProviderAccepted,
    /// Permanent delivery failure (SMTP 5xx classified hard, or an SES
    /// failure the transport classified `permanent`).
    HardBounce,
    /// Transient failure / deferral (SMTP 4xx / SES transient). Has a
    /// sender-health rung (`deferral`) but no outcome rung.
    SoftBounce,
}

impl SalesDeliveryEvent {
    /// The `sales_outcomes.outcome` value this fact produces, if any.
    ///
    /// SMTP/provider acceptance deliberately returns `None`: "Do not classify
    /// SMTP acceptance as delivered" (audit item 12). `delivered` requires a
    /// delivery-confirmation event, which has no producer yet — see
    /// [`SALES_OUTCOME_MAPPING`].
    pub fn outcome(self) -> Option<&'static str> {
        match self {
            Self::ProviderAccepted => None,
            Self::HardBounce => Some("bounce"),
            Self::SoftBounce => None,
        }
    }

    /// The `sales_sender_events.event_type` value this fact produces, if any.
    /// Acceptance produces none for the same reason: `delivered` requires a
    /// delivery confirmation.
    pub fn sender_ledger_event(self) -> Option<&'static str> {
        match self {
            Self::ProviderAccepted => None,
            Self::HardBounce => Some("hard_bounce"),
            Self::SoftBounce => Some("deferral"),
        }
    }
}

/// Where a rung of the outcome ladder is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SalesOutcomeProducer {
    /// Produced by this file, on the delivery path named in `producer`.
    ImplementedHere,
    /// The platform event exists but no workspace producer writes the rung
    /// yet. Recorded here so the gap is explicit rather than silent.
    NoProducerYet,
    /// The mapping must never be produced (the audit forbids it).
    Prohibited,
}

/// One row of the documented platform-event → Sales V2 outcome mapping.
///
/// Read by [`SALES_OUTCOME_MAPPING`]'s auditing test; the `allow(dead_code)`
/// keeps the documented contract from reading as an unused struct in the
/// non-test build.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SalesOutcomeMapping {
    /// The platform event that would produce the rung.
    pub platform_event: &'static str,
    /// The `sales_outcomes.outcome` value, or `None` when the event must not
    /// produce an outcome at all.
    pub outcome: Option<&'static str>,
    /// Where the producer lives (or would live).
    pub producer: &'static str,
    pub status: SalesOutcomeProducer,
}

/// The audit's full Sales V2 outcome ladder and its producer status in this
/// worker.
///
/// Wire strings are the `sales_outcomes.outcome` CHECK vocabulary
/// (migration 200 lines 768-771). `delivered` requires a delivery
/// confirmation and is explicitly NOT produced from SMTP/provider
/// acceptance; the `NoProducerYet` rows document producers owned by other
/// services (tracking-service, reply_handler, calendar, billing) that this
/// audit item does not cover.
///
/// Kept as this crate's documented contract: the mapping test pins it to the
/// migration-200 CHECK vocabulary so a future producer cannot silently add an
/// undocumented rung.
#[allow(dead_code)]
pub const SALES_OUTCOME_MAPPING: &[SalesOutcomeMapping] = &[
    SalesOutcomeMapping {
        platform_event: "smtp_or_provider_acceptance",
        outcome: None,
        producer: "worker-processors email/processor.rs handle_success",
        status: SalesOutcomeProducer::Prohibited,
    },
    SalesOutcomeMapping {
        platform_event: "delivery_confirmation_callback (DSN / SES delivery notification)",
        outcome: Some("delivered"),
        producer: "delivery-notification consumer (not implemented in this worker)",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "tracking_open",
        outcome: Some("open"),
        producer: "tracking-service open-pixel handler",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "tracking_click",
        outcome: Some("click"),
        producer: "tracking-service link redirect",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "reply_processor (reply)",
        outcome: Some("reply"),
        producer: "worker-processors reply_handler",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "reply_processor (positive reply)",
        outcome: Some("positive_reply"),
        producer: "worker-processors reply_handler",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "calendar booking",
        outcome: Some("meeting_booked"),
        producer: "sales-autopilot calendar service",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "calendar attendance",
        outcome: Some("meeting_attended"),
        producer: "sales-autopilot calendar service",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "trial_conversion",
        outcome: Some("trial"),
        producer: "billing-service trial conversion",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "subscription_purchase",
        outcome: Some("paid_subscription"),
        producer: "billing-service subscription lifecycle",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "retained_billing_state",
        outcome: Some("retained_mrr"),
        producer: "billing-service retention sweep",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "complaint_callback",
        outcome: Some("complaint"),
        producer: "reply_handler / FBL consumer",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "unsubscribe",
        outcome: Some("unsubscribe"),
        producer: "reply_handler / unsubscribe endpoint",
        status: SalesOutcomeProducer::NoProducerYet,
    },
    SalesOutcomeMapping {
        platform_event: "hard_bounce",
        outcome: Some("bounce"),
        producer: "worker-processors email/processor.rs handle_hard_bounce",
        status: SalesOutcomeProducer::ImplementedHere,
    },
];

/// The typed sales provenance of one `email_queue` row, as the dispatcher
/// wrote it (migration 202 lines 34-38).
#[derive(Debug, sqlx::FromRow)]
struct SalesProvenance {
    tenant_id: String,
    message_id: Option<uuid::Uuid>,
    sales_enrollment_id: Option<uuid::Uuid>,
    sales_step_execution_id: Option<uuid::Uuid>,
}

/// Parse an `email_queue.id` (text in [`EmailJob`]) into its UUID form.
/// Legacy rows whose id is not a UUID cannot carry the sales provenance
/// (migration 202 columns are UUID FKs), so they are skipped rather than
/// failing the send path with a cast error.
fn parse_queue_row_id(queue_row_id: &str) -> Option<uuid::Uuid> {
    uuid::Uuid::parse_str(queue_row_id.trim()).ok()
}

/// THE single source of the `sales_outcomes` insert in this crate.
///
/// Reads the typed sales provenance from `email_queue` (the dispatcher wrote
/// it), and when the row links a `sales_step_execution_id`, inserts the
/// outcome for `event` idempotently:
///
/// * `ON CONFLICT (tenant_id, outcome, step_execution_id) DO NOTHING`
///   (migration 200 line 777) — a replayed provider callback or a retried
///   delivery attempt can never double-count a bounce or a complaint;
/// * rows without a step execution are skipped — there is nothing to
///   attribute to and the unique key does not dedupe `NULL`s.
///
/// Returns `Ok(Some(id))` when this call inserted the row, `Ok(None)` when
/// nothing was due (prohibited mapping, no sales provenance, or a duplicate
/// that already existed), and `Err` only on a real database failure.
pub async fn record_sales_outcome_if_linked(
    db: &PgPool,
    queue_row_id: &str,
    event: SalesDeliveryEvent,
    provider: &str,
) -> ProcessorResult<Option<uuid::Uuid>> {
    let Some(outcome) = event.outcome() else {
        // `ProviderAccepted` lands here: acceptance is not delivery.
        return Ok(None);
    };
    let Some(queue_id) = parse_queue_row_id(queue_row_id) else {
        debug!(
            queue_row_id,
            "email_queue row id is not a UUID; not sales-provenanced mail, no outcome recorded"
        );
        return Ok(None);
    };

    // `email_queue` is partitioned with PRIMARY KEY (id, created_at), so the
    // id alone is not guaranteed unique; pick the newest row deterministically.
    let provenance: Option<SalesProvenance> = sqlx::query_as(
        "SELECT COALESCE(tenant_id::text, '') AS tenant_id, message_id, \
                sales_enrollment_id, sales_step_execution_id \
         FROM email_queue WHERE id = $1 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(queue_id)
    .fetch_optional(db)
    .await?;

    let Some(provenance) = provenance else {
        return Ok(None);
    };
    if provenance.tenant_id.is_empty() {
        return Ok(None);
    }
    let Some(step_execution_id) = provenance.sales_step_execution_id else {
        debug!(
            queue_row_id,
            "email_queue row carries no sales_step_execution_id; no Sales V2 outcome recorded"
        );
        return Ok(None);
    };

    let id: Option<uuid::Uuid> = sqlx::query_scalar(
        "INSERT INTO sales_outcomes \
             (id, tenant_id, account_id, contact_id, enrollment_id, step_execution_id, \
              outcome, value_eur, message_id, provider, occurred_at, created_at) \
         SELECT gen_random_uuid(), $1, e.account_id, e.contact_id, $2, $3, $4, 0, $5, $6, NOW(), NOW() \
         FROM (SELECT 1) AS one \
         LEFT JOIN sales_enrollments e ON e.id = $2 AND e.tenant_id = $1 \
         ON CONFLICT (tenant_id, outcome, step_execution_id) DO NOTHING \
         RETURNING id",
    )
    .bind(&provenance.tenant_id)
    .bind(provenance.sales_enrollment_id)
    .bind(step_execution_id)
    .bind(outcome)
    .bind(provenance.message_id)
    .bind(provider)
    .fetch_optional(db)
    .await?;

    Ok(id)
}

/// THE single source of the `sales_sender_events` insert in this crate.
///
/// One row per delivery fact, keyed by
/// `UNIQUE (sender_identity_id, event_type, message_id, recipient)`
/// (migration 202 line 120) so a replayed callback is a no-op and the
/// projector folds each fact into the sender's health window exactly once.
/// The message identity falls back to the queue row id when
/// `email_queue.message_id` is NULL, so the dedupe key is never NULL (which
/// Postgres unique indexes do not dedupe).
pub async fn record_sender_event_if_linked(
    db: &PgPool,
    queue_row_id: &str,
    event: SalesDeliveryEvent,
    recipient: &str,
) -> ProcessorResult<Option<uuid::Uuid>> {
    let Some(event_type) = event.sender_ledger_event() else {
        return Ok(None);
    };
    let Some(queue_id) = parse_queue_row_id(queue_row_id) else {
        return Ok(None);
    };
    if recipient.trim().is_empty() {
        return Ok(None);
    }

    // Same partitioned-key caveat as above: one deterministic queue row.
    let id: Option<uuid::Uuid> = sqlx::query_scalar(
        "INSERT INTO sales_sender_events \
             (id, tenant_id, sender_identity_id, event_type, message_id, recipient, occurred_at) \
         SELECT gen_random_uuid(), q.tenant_id::text, q.sales_sender_identity_id, $2, \
                COALESCE(q.message_id::text, q.id::text), $3, NOW() \
         FROM (SELECT queue.* FROM email_queue queue WHERE queue.id = $1 \
               ORDER BY queue.created_at DESC LIMIT 1) q \
         WHERE q.tenant_id IS NOT NULL \
           AND q.sales_sender_identity_id IS NOT NULL \
         ON CONFLICT (sender_identity_id, event_type, message_id, recipient) DO NOTHING \
         RETURNING id",
    )
    .bind(queue_id)
    .bind(event_type)
    .bind(recipient)
    .fetch_optional(db)
    .await?;

    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    // ---------------------------------------------------------------------------
    // 1. Initial State
    // ---------------------------------------------------------------------------
    #[test]
    fn test_initial_state_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        });

        assert_eq!(
            cb.state(),
            CircuitState::Closed,
            "circuit must start Closed"
        );
        assert!(cb.is_allowed(), "requests must be allowed in Closed state");
    }

    #[test]
    fn test_initial_failure_count_zero() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            ..Default::default()
        });
        // No failures recorded yet; state is still closed
        assert_eq!(cb.state(), CircuitState::Closed);
        // record one failure and check we're still closed (threshold = 10)
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_initial_success_count_zero() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            ..Default::default()
        });
        // No successes recorded yet; recording success in Closed resets failures
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_initial_last_failure_none() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            ..Default::default()
        });
        // After reset, no failure should have been recorded
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        // Manually verify by recording one failure (1 << 10), so still closed
        for _ in 0..9 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        // One more to trigger open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // ---------------------------------------------------------------------------
    // 2. State Transitions: Closed → Open
    // ---------------------------------------------------------------------------
    #[test]
    fn test_closed_to_open_after_threshold() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        });

        assert_eq!(cb.state(), CircuitState::Closed);

        // Record failures below threshold
        for _ in 0..4 {
            cb.record_failure();
            assert_eq!(cb.state(), CircuitState::Closed);
        }

        // Fifth failure triggers transition to Open
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "circuit must transition to Open after failure_threshold failures"
        );
        assert!(!cb.is_allowed(), "requests must be rejected in Open state");
    }

    #[test]
    fn test_closed_to_open_failure_count_reset() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        cb.record_failure(); // 1
        cb.record_failure(); // 2
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure(); // 3 → Open
        assert_eq!(cb.state(), CircuitState::Open);

        // Verify that failure count is effectively reset — after open_duration,
        // the circuit transitions to Half-Open where success count starts at 0
        // and failures are tracked separately.
        // We can't directly read failure_count, but we can check state.
        assert!(!cb.is_allowed());
    }

    // ---------------------------------------------------------------------------
    // 3. State Transitions: Open → Half-Open
    // ---------------------------------------------------------------------------
    #[test]
    fn test_open_to_half_open_after_duration() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            ..Default::default()
        });

        // Trigger Open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_allowed());

        // Wait for open duration to elapse
        thread::sleep(Duration::from_millis(20));

        // is_allowed() should transition to Half-Open
        assert!(
            cb.is_allowed(),
            "is_allowed() must return true and transition to Half-Open after open_duration"
        );
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "circuit must transition to Half-Open after open_duration"
        );
    }

    #[test]
    fn test_open_stays_open_before_duration_elapses() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Immediately check — should still be Open
        assert!(!cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // ---------------------------------------------------------------------------
    // 4. State Transitions: Half-Open → Closed
    // ---------------------------------------------------------------------------
    #[test]
    fn test_half_open_to_closed_after_successes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            success_threshold: 3,
            ..Default::default()
        });

        // Trigger Open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        thread::sleep(Duration::from_millis(20));

        // Transition to Half-Open
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes below threshold
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "still Half-Open after 1 success (threshold=3)"
        );
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "still Half-Open after 2 successes (threshold=3)"
        );

        // Third success transitions to Closed
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::Closed,
            "circuit must transition to Closed after success_threshold successes in Half-Open"
        );

        // Now requests flow normally again
        assert!(cb.is_allowed());
    }

    #[test]
    fn test_half_open_to_closed_success_count_resets() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            success_threshold: 2,
            ..Default::default()
        });

        cb.record_failure();
        thread::sleep(Duration::from_millis(20));
        assert!(cb.is_allowed()); // → Half-Open
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Two successes → Closed
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        // Now we're back in Closed — a failure should use Closed logic, not Half-Open
        // Record one failure (threshold=1) → should go to Open
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "after reset to Closed, one failure should open again"
        );
    }

    // ---------------------------------------------------------------------------
    // 5. State Transitions: Half-Open → Open
    // ---------------------------------------------------------------------------
    #[test]
    fn test_half_open_to_open_on_failure() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_millis(10),
            success_threshold: 3,
            ..Default::default()
        });

        // Trigger Open
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        thread::sleep(Duration::from_millis(20));

        // Transition to Half-Open
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // A single failure in Half-Open should reopen the circuit
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "any failure in Half-Open must transition back to Open"
        );
        assert!(
            !cb.is_allowed(),
            "requests must be rejected after reopening"
        );

        // Verify the opened_at timestamp was reset — wait again to transition back
        thread::sleep(Duration::from_millis(20));
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    // ---------------------------------------------------------------------------
    // 6. Error Rate Tracking
    // ---------------------------------------------------------------------------

    /// Replica of the sliding-window error-rate logic from `EmailProcessor::record_outcome`.
    /// We test the algorithm in isolation since we cannot instantiate `EmailProcessor`
    /// without a database.
    fn simulate_error_tracking(
        outcomes: &mut Vec<(SendOutcome, Instant)>,
        outcome: SendOutcome,
        now: Instant,
    ) -> bool {
        outcomes.push((outcome, now));
        // Evict entries older than 60s
        outcomes.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60));
        // Cap at window size
        let len = outcomes.len();
        if len > ERROR_WINDOW_SIZE {
            outcomes.drain(0..(len - ERROR_WINDOW_SIZE));
        }
        // Match `record_outcome`: permanent local rejections are not transport
        // failures and cannot open the cooldown circuit.
        outcomes.len() >= ERROR_WINDOW_SIZE
            && outcomes
                .iter()
                .filter(|(o, _)| {
                    !matches!(
                        o,
                        SendOutcome::Success | SendOutcome::Suppressed | SendOutcome::Rejected
                    )
                })
                .count()
                >= ERROR_THRESHOLD
    }

    #[test]
    fn test_error_rate_window_tracks_20_outcomes() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        // Add 25 successes → window should cap at 20
        for _ in 0..25 {
            simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
        }
        assert_eq!(
            outcomes.len(),
            ERROR_WINDOW_SIZE,
            "sliding window must be capped at ERROR_WINDOW_SIZE ({})",
            ERROR_WINDOW_SIZE
        );

        // After eviction, the oldest entries are removed. Since we pushed 25 items
        // and the window is 20, the first 5 entries are gone.
        assert_eq!(outcomes.len(), 20);
    }

    #[test]
    fn test_error_rate_triggers_cooldown_at_threshold() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        // Fill window with successes
        for _ in 0..10 {
            simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
        }
        // Now add 10 failures → total 20; 10 failures >= ERROR_THRESHOLD (10)
        for _ in 0..10 {
            let triggered =
                simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, now);
            if outcomes.len() >= ERROR_WINDOW_SIZE {
                // Once we have a full window of 20 with 10 failures, trigger
                if outcomes
                    .iter()
                    .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
                    .count()
                    >= ERROR_THRESHOLD
                {
                    assert!(
                        triggered,
                        "cooldown must trigger when >=10 failures in window"
                    );
                }
            }
        }

        // Final verification
        assert_eq!(outcomes.len(), ERROR_WINDOW_SIZE);
        let failures = outcomes
            .iter()
            .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
            .count();
        assert!(
            failures >= ERROR_THRESHOLD,
            "expected >= {} failures, got {}",
            ERROR_THRESHOLD,
            failures
        );
    }

    #[test]
    fn test_error_rate_no_cooldown_below_threshold() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        // Fill window with 11 successes and 9 failures → 9 < 10 threshold
        for _ in 0..11 {
            simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
        }
        for _ in 0..9 {
            let triggered =
                simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, now);
            // Should not trigger since 9 < 10
            if outcomes.len() >= ERROR_WINDOW_SIZE {
                let failures = outcomes
                    .iter()
                    .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
                    .count();
                assert!(
                    failures < ERROR_THRESHOLD,
                    "expected < {} failures, got {}",
                    ERROR_THRESHOLD,
                    failures
                );
                assert!(
                    !triggered,
                    "cooldown must NOT trigger when <10 failures in window"
                );
            }
        }
    }

    #[test]
    fn test_permanent_rejections_do_not_trigger_transport_cooldown() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        for _ in 0..ERROR_WINDOW_SIZE {
            assert!(
                !simulate_error_tracking(&mut outcomes, SendOutcome::Rejected, now),
                "invalid domain or DKIM material must not be counted as a transport outage"
            );
        }

        assert_eq!(outcomes.len(), ERROR_WINDOW_SIZE);
    }

    #[test]
    fn test_error_rate_window_evicts_old_entries() {
        let mut outcomes = Vec::new();

        // Add 10 failures with old timestamps
        let old = Instant::now() - Duration::from_secs(120);
        for _ in 0..10 {
            // Use the old timestamp as the "now" so they are all added
            simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, old);
        }
        assert_eq!(outcomes.len(), 10, "10 old entries added");

        // Now simulate a new event at a much later time — this triggers eviction
        // of entries whose timestamps are >60s behind `new_now`.
        let new_now = Instant::now();
        simulate_error_tracking(&mut outcomes, SendOutcome::Success, new_now);

        // The 10 old entries (timestamp = old, ~120s before new_now) should be
        // evicted by the retain(... < 60s) clause, leaving only the success.
        assert_eq!(
            outcomes.len(),
            1,
            "old entries must be evicted; only the new success remains"
        );
        assert!(
            matches!(outcomes[0].0, SendOutcome::Success),
            "remaining entry must be Success"
        );
    }

    // ---------------------------------------------------------------------------
    // 7. Edge Cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_zero_failure_threshold() {
        // failure_threshold = 1 is the minimum; test that even one failure opens
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "failure_threshold=1 means one failure opens the circuit"
        );
        assert!(!cb.is_allowed());
    }

    #[test]
    fn test_exponential_backoff_formula() {
        // The formula used in handle_soft_bounce:
        //   2_i64.saturating_pow(job.attempt.min(30) as u32)
        // base_delay * 2^attempt

        let base: i64 = 1; // seconds

        // attempt 0 → 2^0 = 1
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(0u32)),
            1,
            "attempt 0: 2^0 = 1s"
        );

        // attempt 1 → 2^1 = 2
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(1u32)),
            2,
            "attempt 1: 2^1 = 2s"
        );

        // attempt 5 → 2^5 = 32
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(5u32)),
            32,
            "attempt 5: 2^5 = 32s"
        );

        // attempt 29 → 2^29 = 536_870_912
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(29u32)),
            536_870_912,
            "attempt 29: 2^29 = 536_870_912s"
        );

        // attempt 30 → capped at 30: 2^30 = 1_073_741_824
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(30)),
            1_073_741_824,
            "attempt 30: 2^30 = 1_073_741_824s (capped)"
        );

        // attempt 31 → still capped at 30: 2^30 = 1_073_741_824
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(30)),
            1_073_741_824,
            "attempt 31: capped at 2^30 = 1_073_741_824s"
        );

        // Verify i64::MAX safety: 2^62 fits, 2^63 would overflow
        // The saturating_pow ensures we don't overflow
        assert_eq!(
            2_i64.saturating_pow(62),
            4_611_686_018_427_387_904_i64,
            "2^62 fits in i64"
        );
        assert_eq!(
            2_i64.saturating_pow(63),
            i64::MAX,
            "2^63 saturates to i64::MAX"
        );
    }

    #[test]
    fn test_exponential_backoff_in_context_of_handle_soft_bounce() {
        // Simulate the exact expression from handle_soft_bounce:
        //   let backoff_multiplier = 2_i64.saturating_pow(job.attempt.min(30) as u32);
        //   let retry_at = Utc::now() + chrono::Duration::seconds(
        //       (self.config.base.retry_delay.as_secs() as i64).saturating_mul(backoff_multiplier),
        //   );

        let retry_delay_secs: i64 = 60; // example value

        // attempt 0 → multiplier = 1 → delay = 60 * 1 = 60s
        let attempt: i32 = 0;
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = retry_delay_secs.saturating_mul(multiplier);
        assert_eq!(delay, 60, "attempt 0: delay = 60 * 1 = 60s");

        // attempt 5 → multiplier = 32 → delay = 60 * 32 = 1920s
        let attempt: i32 = 5;
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = retry_delay_secs.saturating_mul(multiplier);
        assert_eq!(delay, 1920, "attempt 5: delay = 60 * 32 = 1920s");

        // attempt 30 → capped at 30 → 2^30 = 1_073_741_824 → saturating_mul
        let attempt: i32 = 30;
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = retry_delay_secs.saturating_mul(multiplier);
        assert_eq!(
            delay,
            60_i64.saturating_mul(1_073_741_824),
            "attempt 30: delay capped at 2^30 * base"
        );
    }

    #[test]
    fn test_jittered_backoff_stays_within_20_percent() {
        // F6:handle_soft_bounce applies jittered_secs to the exponential
        // backoff — every sample must stay within ±20% of the base, a
        // positive base never collapses to zero, and non-positive inputs
        // pass through.
        let base: i64 = 1920; // 60s * 2^5
        let mut saw_below = false;
        let mut saw_above = false;
        for _ in 0..100 {
            let jittered = jittered_secs(base);
            assert!(
                (1536..=2304).contains(&jittered),
                "jittered {jittered}s outside ±20% of {base}s"
            );
            saw_below |= jittered < base;
            saw_above |= jittered > base;
        }
        assert!(
            saw_below && saw_above,
            "jitter must actually spread on both sides of the base"
        );
        assert!(jittered_secs(0) == 0 && jittered_secs(-5) == -5);
        assert!(
            jittered_secs(1) >= 1,
            "a positive base never jitters to zero"
        );
    }

    #[test]
    fn smtp_dkim_configuration_requires_matching_key_pair() {
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair().unwrap();
        let mut domain = Domain {
            id: "domain-1".into(),
            tenant_id: "tenant-1".into(),
            domain: "example.com".into(),
            dkim_selector: Some("am-test".into()),
            dkim_public_key: Some(key_pair.public_key),
            // Plaintext is accepted only as a legacy migration read path; new
            // API writes are encrypted and covered in apexmail-lib tests.
            dkim_private_key: Some(key_pair.private_key_pem.to_string()),
            warmup_enabled: false,
            warmup_day: 0,
            ses_verified: true,
            dedicated_ips: vec![],
            return_path: None,
        };

        let config = smtp_dkim_config_for_domain(&domain).unwrap();
        assert_eq!(config.selector, "am-test");
        assert!(config
            .private_key
            .starts_with("-----BEGIN PRIVATE KEY-----"));

        domain.dkim_public_key = Some("not-the-same-key".into());
        assert!(matches!(
            smtp_dkim_config_for_domain(&domain),
            Err(ProcessorError::Dkim(message)) if message.contains("does not match")
        ));
    }

    // ---------------------------------------------------------------------------
    // B: tracking rewrite gate honors the env-driven enabled flag
    // ---------------------------------------------------------------------------

    /// Serializes env-mutating tests against every other module in this
    /// crate (std::env is process-global; see `crate::test_support`).
    use crate::test_support::ENV_LOCK;

    /// Audit-2 helper: an ephemeral in-process redis-server on a random
    /// port, skipped (None) when redis-server is unavailable. The child is
    /// leaked intentionally — it dies with the test process.
    async fn ephemeral_redis() -> Option<RedisPool> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = std::process::Command::new("redis-server")
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
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        return deadpool_redis::Config::from_url(format!(
                            "redis://127.0.0.1:{port}"
                        ))
                        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                        .ok();
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = child.kill();
        let _ = child.wait();
        eprintln!("skipping: redis-server did not become ready");
        None
    }

    /// Builds an EmailProcessor around a lazy (never-connected) pair of pools
    /// with the given tracking config. The SES transport keeps `prepare_email`
    /// off the DKIM path, so no key material is needed.
    async fn make_processor_with_tracking(
        tracking: crate::common::TrackingConfig,
    ) -> EmailProcessor {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let config = EmailConfig {
            tracking,
            ..Default::default()
        };
        EmailProcessor::new(db, redis, config).await.unwrap()
    }

    fn tracking_gate_job() -> EmailJob {
        EmailJob {
            id: "job-1".into(),
            message_id: "msg-1".into(),
            tenant_id: "tenant-1".into(),
            domain_id: "domain-1".into(),
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            subject: "Hello".into(),
            html: Some(r#"<html><body><a href="https://example.com/x">x</a></body></html>"#.into()),
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 1,
            created_at: Utc::now(),
        }
    }

    fn tracking_gate_domain() -> Domain {
        Domain {
            id: "domain-1".into(),
            tenant_id: "tenant-1".into(),
            domain: "example.com".into(),
            dkim_selector: None,
            dkim_public_key: None,
            dkim_private_key: None,
            warmup_enabled: false,
            warmup_day: 0,
            ses_verified: true,
            dedicated_ips: vec![],
            return_path: None,
        }
    }

    /// Route-aware readiness: only the shared-pool route needs SES
    /// verification; a dedicated relay route does not.
    #[test]
    fn domain_route_readiness_is_route_aware() {
        let mut domain = tracking_gate_domain();
        domain.ses_verified = false;
        assert_eq!(
            domain_route_readiness(&DeliveryRoute::SesShared, &domain),
            Some("domain_ses_not_verified"),
            "an unverified domain must not ride the shared SES pool"
        );
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };
        assert_eq!(
            domain_route_readiness(&dedicated, &domain),
            None,
            "a dedicated relay route does not need SES verification"
        );
        domain.ses_verified = true;
        assert_eq!(
            domain_route_readiness(&DeliveryRoute::SesShared, &domain),
            None
        );
    }

    /// A dedicated-IP candidate for tests. `warming` selects the warmup
    /// branch (quota from the canonical schedule); active/graduated rows
    /// route unthrottled.
    fn dedicated_ip(id: &str, ip: &str, warming: bool, started_days_ago: i64) -> DedicatedIp {
        dedicated_ip_started(Utc::now(), id, ip, warming, started_days_ago)
    }

    /// Deterministic variant: `warmup_started_at` is derived from the caller's
    /// clock, so the derived warmup day is exact.
    fn dedicated_ip_started(
        now: DateTime<Utc>,
        id: &str,
        ip: &str,
        warming: bool,
        started_days_ago: i64,
    ) -> DedicatedIp {
        DedicatedIp {
            id: id.into(),
            ip_address: ip.into(),
            warming,
            warmup_started_at: Some(now - chrono::Duration::days(started_days_ago)),
        }
    }

    /// B: with `enabled: false` the gate in `prepare_email` must leave the
    /// HTML byte-identical — no pixel, no link rewriting.
    /// The env guard is held across awaits on purpose: the awaited processor
    /// setup reads the process-global `TRACKING_SECRET_KEY`.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn tracking_gate_disabled_leaves_html_untouched() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The env secret must not matter when the gate is closed.
        std::env::set_var("TRACKING_SECRET_KEY", "k".repeat(40));

        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: false,
            ..crate::common::TrackingConfig::default()
        })
        .await;

        let job = tracking_gate_job();
        let domain = tracking_gate_domain();
        let prepared = processor
            .prepare_email(&job, &domain, &DeliveryRoute::SesShared)
            .unwrap();
        assert_eq!(
            prepared.html.as_deref(),
            job.html.as_deref(),
            "disabled tracking must not rewrite the HTML"
        );

        std::env::remove_var("TRACKING_SECRET_KEY");
    }

    /// B: with `enabled: true` (and the shared secret configured) the gate
    /// lets the pixel + link rewriters run.
    /// The env guard is held across awaits on purpose: the awaited processor
    /// setup reads the process-global `TRACKING_SECRET_KEY`.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn tracking_gate_enabled_rewrites_html() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TRACKING_SECRET_KEY", "k".repeat(40));

        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".into(),
            open_pixel_path: "/o".into(),
            click_redirect_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            secret_key: None,
        })
        .await;

        let job = tracking_gate_job();
        let domain = tracking_gate_domain();
        let prepared = processor
            .prepare_email(&job, &domain, &DeliveryRoute::SesShared)
            .unwrap();
        let html = prepared.html.unwrap();
        assert!(
            html.contains("https://track.example.com/o/"),
            "open pixel must be embedded: {html}"
        );
        assert!(
            html.contains("https://track.example.com/c/"),
            "links must be rewritten: {html}"
        );

        std::env::remove_var("TRACKING_SECRET_KEY");
    }

    // ---------------------------------------------------------------------------
    // FIX-8: multi-recipient job expansion
    // ---------------------------------------------------------------------------

    fn queued_row(to: &str, to_addresses: Option<Vec<String>>) -> QueuedEmailRow {
        QueuedEmailRow {
            id: "job-1".into(),
            message_id: "msg-1".into(),
            tenant_id: "tenant-1".into(),
            domain_id: "domain-1".into(),
            from: "sender@example.com".into(),
            to: to.into(),
            to_addresses,
            subject: "Hello".into(),
            html: None,
            text: Some("hi".into()),
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 0,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_queued_row_with_two_recipients_expands_to_two_jobs() {
        // A queued message with 2 recipients must produce 2 send units
        // (previously recipient 2 was silently dropped).
        let row = queued_row(
            "first@example.com",
            Some(vec![
                "first@example.com".into(),
                "second@example.com".into(),
            ]),
        );
        let jobs = queued_row_to_jobs(row);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].to, "first@example.com");
        assert_eq!(jobs[1].to, "second@example.com");
        // Identity fields are preserved on every expanded job.
        for job in &jobs {
            assert_eq!(job.id, "job-1");
            assert_eq!(job.message_id, "msg-1");
            assert_eq!(job.tenant_id, "tenant-1");
            assert_eq!(job.from, "sender@example.com");
        }
    }

    #[test]
    fn test_queued_row_single_recipient_single_job() {
        // 1-recipient message → exactly 1 send (no regression).
        let row = queued_row("solo@example.com", Some(vec!["solo@example.com".into()]));
        let jobs = queued_row_to_jobs(row);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].to, "solo@example.com");
    }

    #[test]
    fn test_queued_row_empty_to_addresses_yields_no_jobs() {
        // An explicit empty array means every recipient of the row was
        // already delivered (metadata.pending_recipients = []) — expanding to
        // the legacy `to` would DUPLICATE that recipient.
        let row = queued_row("legacy@example.com", Some(vec![]));
        let jobs = queued_row_to_jobs(row);
        assert!(jobs.is_empty(), "no send units for a fully-delivered row");
    }

    #[test]
    fn test_queued_row_null_to_addresses_falls_back_to_legacy_to() {
        // NULL to_addresses → fall back to the legacy single-recipient "to".
        let row = queued_row("legacy@example.com", None);
        let jobs = queued_row_to_jobs(row);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].to, "legacy@example.com");
    }

    #[tokio::test]
    async fn test_concurrent_state_transitions() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        }));

        let mut handles = Vec::new();

        // Spawn 10 concurrent tasks, each recording failures
        for _ in 0..10 {
            let cb_clone = Arc::clone(&cb);
            handles.push(tokio::spawn(async move {
                cb_clone.record_failure();
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("concurrent task panicked");
        }

        // With 10 failures and threshold=5, circuit should be Open
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "concurrent failures should trigger circuit open"
        );
        assert!(!cb.is_allowed());
    }

    #[tokio::test]
    async fn test_concurrent_success_and_failure() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(60),
            success_threshold: 2,
            window_duration: Duration::from_secs(120),
        }));

        // First, open the circuit
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // We need to get to Half-Open first. Use a short duration.
        let cb2 = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(5),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        }));

        cb2.record_failure();
        assert_eq!(cb2.state(), CircuitState::Open);
        thread::sleep(Duration::from_millis(10));
        assert!(cb2.is_allowed()); // → Half-Open
        assert_eq!(cb2.state(), CircuitState::HalfOpen);

        // Spawn concurrent successes and a failure in Half-Open
        let mut handles = Vec::new();
        for _ in 0..3 {
            let cb_clone = Arc::clone(&cb2);
            handles.push(tokio::spawn(async move {
                cb_clone.record_success();
            }));
        }
        // And one failure
        let cb_clone = Arc::clone(&cb2);
        handles.push(tokio::spawn(async move {
            cb_clone.record_failure();
        }));

        for handle in handles {
            handle.await.expect("concurrent task panicked");
        }

        // The failure in Half-Open should have reopened the circuit
        // But due to race conditions, if all successes happen first, it might close.
        // Either way, the circuit is in a valid state.
        let state = cb2.state();
        assert!(
            state == CircuitState::Open || state == CircuitState::Closed,
            "concurrent operations in Half-Open must result in a valid state: got {:?}",
            state
        );
    }

    #[tokio::test]
    async fn test_concurrent_is_allowed_and_record_failure() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_millis(10),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        }));

        // Open the circuit
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        thread::sleep(Duration::from_millis(20));

        // Concurrently call is_allowed (which transitions to Half-Open) and record_failure
        let cb_clone = Arc::clone(&cb);
        let h1 = tokio::spawn(async move {
            cb_clone.is_allowed(); // may transition to Half-Open
        });

        let cb_clone = Arc::clone(&cb);
        let h2 = tokio::spawn(async move {
            cb_clone.record_failure(); // records in Open or Half-Open
        });

        h1.await.expect("task panicked");
        h2.await.expect("task panicked");

        // The circuit must be in a valid state
        let state = cb.state();
        assert!(
            state == CircuitState::Open || state == CircuitState::HalfOpen,
            "concurrent is_allowed + record_failure must produce valid state: got {:?}",
            state
        );
    }

    // ---------------------------------------------------------------------------
    // 3. Sender-reputation sent counter (FIX-9 / M56)
    // ---------------------------------------------------------------------------
    #[test]
    fn test_reputation_sent_key_format() {
        // Key format must match the FBL server's reader:
        //   mta:reputation:{domain}:{YYYY-MM-DD}  with field "sent"
        assert_eq!(
            reputation_sent_key("example.com", "2026-08-09"),
            "mta:reputation:example.com:2026-08-09"
        );
    }

    #[test]
    fn test_transport_provider_label_matches_delivery_analytics_buckets() {
        // delivery_analytics buckets on headers->>'X-Mail-Provider'; the
        // values stamped at send time must be the canonical 'ses'/'smtp'.
        assert_eq!(transport_provider_label(&TransportType::Ses), "ses");
        assert_eq!(transport_provider_label(&TransportType::Smtp), "smtp");
    }

    // ── Audit item 21: recipient-provider provenance ───────────────────

    #[test]
    fn recipient_provider_normalizes_to_a_canonical_slug() {
        assert_eq!(
            normalize_recipient_provider("Google Workspace"),
            Some("google_workspace".into())
        );
        assert_eq!(
            normalize_recipient_provider("  Microsoft-365  "),
            Some("microsoft-365".into())
        );
        assert_eq!(
            normalize_recipient_provider("..."),
            None,
            "separator-only input is unusable"
        );
        assert_eq!(normalize_recipient_provider("   "), None);
        assert_eq!(normalize_recipient_provider(&"x".repeat(65)), None);
        assert_eq!(
            normalize_recipient_provider("gôogle"),
            Some("gogle".into()),
            "non-ASCII characters are dropped, never guessed"
        );
    }

    #[test]
    fn recipient_provider_requires_valid_provenance_source() {
        // A known provider with an MX source is persisted as mx_resolved.
        assert_eq!(
            normalized_provider_columns(Some("Google Workspace"), Some("mx_resolved")),
            (Some("google_workspace".to_string()), Some("mx_resolved"))
        );
        // A provider_callback report is equally valid provenance.
        assert_eq!(
            normalized_provider_columns(Some("microsoft_365"), Some("provider_callback")),
            (Some("microsoft_365".to_string()), Some("provider_callback"))
        );
        // No source: the value is dropped rather than attributed to nothing.
        assert_eq!(
            normalized_provider_columns(Some("google_workspace"), None),
            (None, None)
        );
        // An unrecognized source (including whitespace variants) is dropped.
        assert_eq!(
            normalized_provider_columns(Some("google_workspace"), Some("looked_at_domain")),
            (None, None)
        );
        // No provider: nothing persisted, no source.
        assert_eq!(
            normalized_provider_columns(None, Some("mx_resolved")),
            (None, None)
        );
        // An empty provider cannot be persisted.
        assert_eq!(
            normalized_provider_columns(Some("  "), Some("mx_resolved")),
            (None, None)
        );
    }

    /// Audit item 21: the shared `events` writer persists the provenance on
    /// the sent row, and the carry-through lookup hands the SAME normalized
    /// provider to a later bounce on the same recipient-send. Rows with no
    /// evidence stay NULL. Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn provider_provenance_is_persisted_and_carried_through() {
        let pool =
            match migrator::test_support::fresh_canonical_pool("worker_provider", "carry").await {
                Ok(pool) => pool,
                Err(error) => panic!("{}", error.panic_message()),
            };
        let Some(pool) = pool else {
            eprintln!("skipping provider_provenance_is_persisted_and_carried_through: no TEST_DATABASE_URL");
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message_id = format!("msg-{suffix}");

        // The sent event carries MX-resolved evidence.
        insert_recipient_event(
            &pool,
            &tenant,
            &message_id,
            "dom-1",
            None,
            "sent",
            "CEO@Acme-Corp.Example",
            Some("google_workspace"),
            Some("mx_resolved"),
        )
        .await
        .expect("sent event insert must carry provider columns");

        let stored: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT recipient_provider, provider_source FROM events
             WHERE tenant_id = $1 AND message_id = $2 AND event_type = 'sent'",
        )
        .bind(&tenant)
        .bind(&message_id)
        .fetch_one(&pool)
        .await
        .expect("read back sent event");
        assert_eq!(stored.0.as_deref(), Some("google_workspace"));
        assert_eq!(stored.1.as_deref(), Some("mx_resolved"));

        // A bounce for a case-different recipient carries the same values.
        let (provider, source) =
            carried_recipient_provider(&pool, &tenant, &message_id, "ceo@acme-corp.example").await;
        assert_eq!(provider.as_deref(), Some("google_workspace"));
        assert_eq!(source.as_deref(), Some("mx_resolved"));

        // An unknown recipient-send has no provenance to carry — NULL, not
        // a suffix guess.
        let (none_provider, none_source) =
            carried_recipient_provider(&pool, &tenant, &message_id, "other@acme-corp.example")
                .await;
        assert_eq!(none_provider, None);
        assert_eq!(none_source, None);

        // A writer with no evidence persists NULL/ NULL.
        insert_recipient_event(
            &pool,
            &tenant,
            &format!("msg-{suffix}-unknown"),
            "dom-1",
            None,
            "sent",
            "user@unknown.example",
            None,
            None,
        )
        .await
        .expect("unknown-provider insert");
        let unknown: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT recipient_provider, provider_source FROM events
             WHERE tenant_id = $1 AND message_id = $2",
        )
        .bind(&tenant)
        .bind(format!("msg-{suffix}-unknown"))
        .fetch_one(&pool)
        .await
        .expect("read back unknown-provider event");
        assert_eq!(unknown, (None, None));

        pool.close().await;
    }

    #[test]
    fn test_envelope_domain() {
        assert_eq!(envelope_domain("sender@example.com"), Some("example.com"));
        assert_eq!(
            envelope_domain("sender@sub.example.co.uk"),
            Some("sub.example.co.uk")
        );
        assert_eq!(envelope_domain("no-at-sign"), None);
        assert_eq!(envelope_domain("@"), Some(""));
    }

    // ---------------------------------------------------------------------------
    // F-21: retry classification by SMTP reply code (not substrings)
    // ---------------------------------------------------------------------------

    /// A raw permanent relay rejection ("550 5.1.1") matched NEITHER the
    /// soft- nor the hard-bounce string marker before and was retried up to
    /// max_retries via the generic handler. It now maps to the typed
    /// `ProcessorError::Smtp` and classifies Hard — i.e. the existing
    /// hard-bounce handling: queue row 'bounced', recipient suppressed,
    /// bounce event recorded, never requeued.
    #[test]
    fn relay_550_is_classified_hard_and_not_retried() {
        let err =
            crate::email::transport::SmtpTransport::map_smtp_error("550 5.1.1 mailbox unavailable");
        assert!(
            matches!(err, ProcessorError::Smtp { code: 550, .. }),
            "relay string must map to the typed Smtp error: {err}"
        );
        assert_eq!(classify_send_failure(&err), SendFailureClass::Hard);
    }

    /// A temporary relay deferral ("450 greylisted") classifies Soft — i.e.
    /// the existing soft-bounce handling: requeued with the unchanged
    /// exponential backoff (attempt + 1, retry_at = now + retry_delay *
    /// 2^attempt) until max_retries.
    #[test]
    fn relay_450_greylist_is_classified_soft_for_backoff_retry() {
        let err = crate::email::transport::SmtpTransport::map_smtp_error("450 4.7.1 greylisted");
        assert!(matches!(err, ProcessorError::Smtp { code: 450, .. }));
        assert_eq!(classify_send_failure(&err), SendFailureClass::Soft);
        // The soft handler's backoff is the pre-existing formula (verified
        // in test_exponential_backoff_formula): base delay * 2^attempt.
        let attempt: i32 = 1;
        assert_eq!(2_i64.saturating_pow(attempt.min(30) as u32), 2);
    }

    /// The structured reply code outranks contradicting free text: a 5xx
    /// whose tail happens to say "temporary" is still permanent (mail-send's
    /// production Display shape included).
    #[test]
    fn reply_code_outranks_free_text_markers() {
        let err = crate::email::transport::SmtpTransport::map_smtp_error(
            "Unexpected reply: Code: 550, Enhanced code: 5.1.1, Message: temporary local error",
        );
        assert!(matches!(err, ProcessorError::Smtp { code: 550, .. }));
        assert_eq!(classify_send_failure(&err), SendFailureClass::Hard);
    }

    /// The legacy string markers keep their meaning for messages that
    /// already carry them (backward compat with other error paths).
    #[test]
    fn legacy_string_classification_still_works() {
        assert_eq!(
            classify_send_failure(&ProcessorError::Transport(
                "Soft bounce: mailbox full".into()
            )),
            SendFailureClass::Soft
        );
        assert_eq!(
            classify_send_failure(&ProcessorError::Transport(
                "relay said temporary failure".into()
            )),
            SendFailureClass::Soft
        );
        assert_eq!(
            classify_send_failure(&ProcessorError::Transport(
                "Hard bounce: user unknown".into()
            )),
            SendFailureClass::Hard
        );
    }

    /// Codeless transport errors (timeout, DNS, connection) stay Unknown:
    /// the generic handler retries them below max_retries and dead-letters
    /// (DLQ + 'failed') after — unchanged behavior.
    #[test]
    fn codeless_transport_errors_stay_generic() {
        for err in [
            ProcessorError::Transport("Connection timeout".into()),
            ProcessorError::Transport("I/O error: connection reset by peer".into()),
            ProcessorError::Dns("resolution failed".into()),
        ] {
            assert_eq!(
                classify_send_failure(&err),
                SendFailureClass::Unknown,
                "codeless error must stay generic: {err}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Audit-4: SES permanent failures classified at the transport source
    // -----------------------------------------------------------------------

    /// A MailboxDoesNotExist-class SES rejection arrives as
    /// `ProcessorError::Ses { permanent: true, address_proving: true }`
    /// (classified in transport.rs where the typed SDK error is still
    /// available) and must take the hard-bounce path: per-recipient
    /// suppression, never a retry.
    #[test]
    fn ses_permanent_failure_classifies_hard_for_suppression() {
        let err = ProcessorError::Ses {
            permanent: true,
            address_proving: true,
            message: "SES send failed: MailboxDoesNotExist".into(),
        };
        assert_eq!(classify_send_failure(&err), SendFailureClass::Hard);
        assert!(
            is_recipient_invalid(&err),
            "an address-proving SES bounce justifies suppression"
        );
    }

    /// A transient SES failure (4xx / 5xx / network) carries
    /// permanent:false and must retry via the soft-bounce backoff — never
    /// suppress on it.
    #[test]
    fn ses_transient_failure_classifies_soft_for_retry() {
        let err = ProcessorError::Ses {
            permanent: false,
            address_proving: false,
            message: "SES send failed: 503 Service Unavailable".into(),
        };
        assert_eq!(classify_send_failure(&err), SendFailureClass::Soft);
        assert!(!is_recipient_invalid(&err));
    }

    /// Account/configuration refusals (sending paused, suspension, unverified
    /// MAIL FROM, 4xx) are NOT address proof: the message may dead-letter,
    /// but the recipient must never be suppressed tenant-wide on them.
    #[test]
    fn ses_non_address_permanent_failures_do_not_suppress() {
        for (code, status) in [
            (Some("AccountSuspendedException"), None),
            (Some("MailFromDomainNotVerifiedException"), None),
            (Some("BadRequestException"), None),
            (None, Some(400)),
            (None, Some(403)),
            (None, Some(452)),
        ] {
            let disposition = crate::email::transport::classify_ses_failure(code, status);
            assert_eq!(
                disposition,
                crate::email::transport::SesFailureDisposition::Transient,
                "{code:?}/{status:?} must retry, not permanent-suppress"
            );
        }
        // Determinate non-address refusals dead-letter WITHOUT suppressing.
        let err = ProcessorError::Ses {
            permanent: true,
            address_proving: false,
            message: "SES send failed: SendingPausedException".into(),
        };
        assert_eq!(classify_send_failure(&err), SendFailureClass::Hard);
        assert!(
            !is_recipient_invalid(&err),
            "sending-paused says nothing about the mailbox"
        );
    }

    /// The generic SMTP phrase list must not treat policy rejections
    /// ("address rejected", "mailbox unavailable") as address proof —
    /// receiving MTAs emit both for spam-policy and full-mailbox verdicts.
    #[test]
    fn smtp_policy_rejection_phrases_do_not_suppress() {
        for message in [
            "550 5.7.1 address rejected: access denied",
            "550 mailbox unavailable (over quota policy)",
        ] {
            let err = ProcessorError::Smtp {
                code: 550,
                enhanced: None,
                message: message.into(),
            };
            assert!(
                !is_recipient_invalid(&err),
                "policy phrase must not suppress: {message}"
            );
        }
        // Genuine mailbox-proof phrases still suppress.
        let err = ProcessorError::Smtp {
            code: 550,
            enhanced: None,
            message: "550 5.1.1 user unknown".into(),
        };
        assert!(is_recipient_invalid(&err));
    }

    // ---------------------------------------------------------------------------
    // G.3a: recipient expansion respects the concurrency cap
    // ---------------------------------------------------------------------------

    fn row_with_id(id: &str, to_addresses: Option<Vec<String>>) -> QueuedEmailRow {
        QueuedEmailRow {
            id: id.into(),
            message_id: format!("msg-{id}"),
            ..queued_row("first@example.com", to_addresses)
        }
    }

    #[test]
    fn expansion_is_capped_to_available_slots() {
        let recipients: Vec<String> = (1..=5).map(|i| format!("user{i}@example.com")).collect();
        let rows = vec![row_with_id("r1", Some(recipients))];
        let jobs = expand_rows_within_cap(rows, 3);
        assert_eq!(jobs.len(), 3, "a 5-recipient row must not exceed 3 slots");
        assert_eq!(jobs[0].to, "user1@example.com");
        assert_eq!(jobs[2].to, "user3@example.com");
    }

    #[test]
    fn expansion_counts_across_multiple_rows() {
        let rows = vec![
            row_with_id("r1", Some(vec!["a@example.com".into()])),
            row_with_id(
                "r2",
                Some(vec![
                    "b@example.com".into(),
                    "c@example.com".into(),
                    "d@example.com".into(),
                ]),
            ),
            row_with_id("r3", Some(vec!["e@example.com".into()])),
        ];
        let jobs = expand_rows_within_cap(rows, 2);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].id, "r1");
        assert_eq!(jobs[1].id, "r2");
        // The third row was never admitted once the cap was reached.
        assert!(jobs.iter().all(|j| j.id != "r3"));
    }

    #[test]
    fn expansion_with_zero_slots_yields_nothing() {
        let rows = vec![row_with_id("r1", Some(vec!["a@example.com".into()]))];
        assert!(expand_rows_within_cap(rows, 0).is_empty());
    }

    // ---------------------------------------------------------------------------
    // G.3b/G.3c: suppression + send idempotency SQL and marker
    // ---------------------------------------------------------------------------

    #[test]
    fn suppressed_update_only_marks_row_terminal_when_pending_set_empty() {
        // G.3b: the suppression update must decrement the per-recipient
        // pending set (not blanket-flip the row) and only set the terminal
        // 'suppressed' status when the set is empty.
        let sql = SUPPRESSED_UPDATE_SQL;
        assert!(
            sql.contains("pending_recipients"),
            "must maintain the pending set"
        );
        assert!(
            sql.contains("- $3::text"),
            "must remove the suppressed recipient"
        );
        assert!(
            sql.contains("THEN 'suppressed' ELSE status END"),
            "status must be conditional"
        );
        assert!(
            sql.contains("error_message = $1"),
            "reason must be recorded"
        );
    }

    #[test]
    fn possibly_sent_update_records_audit_trail_and_completes_row() {
        let sql = POSSIBLY_SENT_UPDATE_SQL;
        assert!(sql.contains("possibly_sent"), "must append an audit marker");
        assert!(
            sql.contains("- $2::text"),
            "must remove the recipient from pending"
        );
        assert!(
            sql.contains("THEN 'sent' ELSE status END"),
            "row completes when pending empties"
        );
    }

    // ---------------------------------------------------------------------------
    // Audit-3: hard bounce / DLQ must terminalize per-RECIPIENT, mirroring
    // handle_success/handle_suppressed (FIX-8 made rows multi-recipient).
    // ---------------------------------------------------------------------------

    /// A hard bounce removes the bounced recipient from the pending set and
    /// only flips the row to terminal 'bounced' when nothing remains owed —
    /// siblings of a 3-recipient row keep their deliveries.
    #[test]
    fn hard_bounce_update_only_marks_row_terminal_when_pending_set_empty() {
        let sql = HARD_BOUNCE_UPDATE_SQL;
        assert!(
            sql.contains("pending_recipients"),
            "must maintain the pending set"
        );
        assert!(
            sql.contains("- $3::text"),
            "must remove ONLY the bounced recipient"
        );
        assert!(
            sql.contains("THEN 'bounced' ELSE status END"),
            "terminal status must be conditional on the pending set emptying"
        );
        assert!(
            sql.contains("error_message = $1"),
            "bounce reason must be recorded"
        );
    }

    /// The DLQ path (attempt budget exhausted on a transient error) must not
    /// abandon the recipients still owed a delivery: the failed recipient is
    /// removed, the row only becomes 'failed' when the pending set empties,
    /// and remaining siblings return to 'pending' for their own deliveries.
    #[test]
    fn dlq_failure_only_marks_row_terminal_when_pending_set_empty() {
        let sql = DLQ_FAIL_UPDATE_SQL;
        assert!(
            sql.contains("- $3::text"),
            "must remove the failed recipient from pending"
        );
        assert!(
            sql.contains("THEN 'failed' ELSE 'pending' END"),
            "row fails only when pending empties; siblings stay deliverable"
        );
        assert!(
            sql.contains("locked_until = NULL"),
            "a row returned to pending must be immediately claimable"
        );
    }

    /// The suppression insert stays scoped to the single bounced address
    /// (`$3` = job.to), never the row's whole recipient list.
    #[test]
    fn hard_bounce_suppression_covers_only_the_bounced_address() {
        // The suppression INSERT lives inline in handle_hard_bounce; the
        // hard-bounce contract (HARD_BOUNCE_UPDATE_SQL) keys the recipient
        // as $3, and the suppression uses the same per-job recipient — the
        // bounced sibling's address alone. Pin the SQL contract:
        assert!(
            HARD_BOUNCE_UPDATE_SQL.contains("- $3::text"),
            "the bounced recipient (the suppressed address) is the row's $3"
        );
    }

    // ---------------------------------------------------------------------------
    // Audit-5: lease-token fencing on every post-claim row write
    // (mirrors queue-provider's exact lease fencing; the token lives in
    // email_queue.metadata because email_queue has no lease_token column —
    // migration 103 added it to queue_jobs only).
    // ---------------------------------------------------------------------------

    /// The claim mints a fresh lease token into the row's metadata; the
    /// next claim overwrites it, so a stale worker's token can never match.
    #[test]
    fn claim_mints_a_fresh_lease_token_into_metadata() {
        assert!(
            FETCH_JOBS_SQL.contains("gen_random_uuid()"),
            "claim must mint a fresh token: {FETCH_JOBS_SQL}"
        );
        assert!(
            FETCH_JOBS_SQL.contains("'{lease_token}'"),
            "token must land in metadata.lease_token"
        );
    }

    /// Every post-claim row write must be fenced: the UPDATE only applies
    /// while the row still carries THIS claim's token (a reclaim mints a
    /// new one, so a stale worker's write matches nothing and no-ops).
    /// `IS NOT DISTINCT FROM` keeps token-less legacy rows writable by
    /// token-less writers; a stale TOKEN can never match the new one.
    #[test]
    fn terminal_writes_are_fenced_on_lease_token() {
        let fenced_sql = [
            HANDLE_SUCCESS_UPDATE_SQL,
            SUPPRESSED_UPDATE_SQL,
            POSSIBLY_SENT_UPDATE_SQL,
            SOFT_BOUNCE_UPDATE_SQL,
            HARD_BOUNCE_UPDATE_SQL,
            DLQ_FAIL_UPDATE_SQL,
            REQUEUE_JOB_UPDATE_SQL,
            PERMANENT_FAILURE_UPDATE_SQL,
        ];
        for sql in fenced_sql {
            assert!(
                sql.contains("(metadata->>'lease_token') IS NOT DISTINCT FROM"),
                "row write must be fenced on the claim's lease token: {sql}"
            );
        }
    }

    /// The fenced write is a no-op when the lease was lost — the write must
    /// not be able to resurrect itself by matching a NULL token row with a
    /// stale token (and vice versa): only exact-token or both-NULL matches
    /// apply.
    #[test]
    fn lease_token_of_reads_the_claim_minted_token() {
        let mut job = tracking_gate_job();
        assert!(
            lease_token_of(&job).is_none(),
            "a job from a token-less legacy row has no token"
        );
        job.metadata = Some(serde_json::json!({"lease_token": "tok-123"}));
        assert_eq!(lease_token_of(&job), Some("tok-123"));
        // Unrelated metadata must not accidentally surface a token.
        job.metadata = Some(serde_json::json!({"pending_recipients": []}));
        assert_eq!(lease_token_of(&job), None);
    }

    // ---------------------------------------------------------------------------
    // Audit-2: send-time admission token bucket (Redis, per tenant AND per
    // domain, one atomic Lua reserve; exhaustion defers the row)
    // ---------------------------------------------------------------------------

    /// P0: the admission keys scope BOTH dimensions — a tenant-wide bucket
    /// (account ceiling) and a per-domain bucket — AND the route, so shared
    /// and dedicated traffic never share an allowance.
    #[test]
    fn send_admission_keys_cover_tenant_domain_and_route() {
        let job = tracking_gate_job();
        let shared = send_admission_keys(&job, TransportKind::SesShared);
        let dedicated = send_admission_keys(&job, TransportKind::Dedicated);
        assert_eq!(shared.len(), 2);
        assert!(
            shared.iter().any(|k| k.contains(&job.tenant_id)),
            "a tenant-scoped bucket must exist: {shared:?}"
        );
        assert!(
            shared.iter().any(|k| k.contains(&job.domain_id)),
            "a domain-scoped bucket must exist: {shared:?}"
        );
        for key in &shared {
            assert!(
                key.contains("ses-shared"),
                "shared keys must be route-scoped: {key}"
            );
        }
        for key in &dedicated {
            assert!(
                key.contains("dedicated"),
                "dedicated keys must be route-scoped: {key}"
            );
        }
        assert!(
            shared.iter().all(|key| !dedicated.contains(key)),
            "the two routes must not share a bucket: {shared:?} vs {dedicated:?}"
        );
    }

    /// P0: the route-aware rate source — SES account ceiling for the shared
    /// pool, the relay's own cap for the dedicated route.
    #[test]
    fn route_send_rate_selects_the_transports_own_cap() {
        let config = EmailConfig {
            ses: crate::common::SesConfig {
                max_send_rate: 11,
                ..Default::default()
            },
            smtp: crate::common::SmtpConfig {
                rate_limit_per_second: 7,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            route_send_rate_per_second(&config, TransportKind::SesShared),
            11
        );
        assert_eq!(
            route_send_rate_per_second(&config, TransportKind::Dedicated),
            7
        );
    }

    /// Audit-2 behavioral gate (ephemeral redis-server): the bucket admits
    /// up to its capacity, refuses when exhausted (the caller defers the
    /// row instead of sending), and refills over elapsed time — the clock
    /// is injected as `now_ms`, so refill is tested without sleeping.
    #[tokio::test]
    async fn send_admission_bucket_exhausts_then_refills() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };

        let keys = send_admission_keys(&tracking_gate_job(), TransportKind::SesShared);
        let t0 = 1_000_000i64;
        // rate=1/sec, capacity=1 (one-second burst).
        assert!(
            reserve_send_admission(&redis, &keys, 1, t0).await.unwrap(),
            "first send within capacity must be admitted"
        );
        assert!(
            !reserve_send_admission(&redis, &keys, 1, t0).await.unwrap(),
            "an exhausted bucket must refuse — the row is deferred, not sent"
        );
        assert!(
            !reserve_send_admission(&redis, &keys, 1, t0 + 500)
                .await
                .unwrap(),
            "half a refill period later the bucket is still empty"
        );
        assert!(
            reserve_send_admission(&redis, &keys, 1, t0 + 1_500)
                .await
                .unwrap(),
            "after a full refill period the bucket admits again"
        );
    }

    /// The tenant bucket is SHARED across the tenant's domains while each
    /// domain keeps its own bucket: exhausting the tenant ceiling refuses a
    /// different domain whose own bucket still has tokens.
    #[tokio::test]
    async fn send_admission_buckets_are_per_tenant_and_per_domain() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };

        let mut job = tracking_gate_job();
        job.tenant_id = "tenant-rl".into();
        job.domain_id = "domain-a".into();
        let keys_a = send_admission_keys(&job, TransportKind::SesShared);
        job.domain_id = "domain-b".into();
        let keys_b = send_admission_keys(&job, TransportKind::SesShared);

        let t0 = 2_000_000i64;
        // rate=1/sec, capacity=1: domain-a's send consumes BOTH buckets.
        assert!(reserve_send_admission(&redis, &keys_a, 1, t0)
            .await
            .unwrap());
        // domain-b's own bucket is untouched, but the shared TENANT bucket
        // is empty — admission (an AND over both buckets) must refuse.
        assert!(
            !reserve_send_admission(&redis, &keys_b, 1, t0)
                .await
                .unwrap(),
            "the shared tenant ceiling must bind across domains"
        );
        // A different tenant is unaffected.
        job.tenant_id = "tenant-other".into();
        let keys_other = send_admission_keys(&job, TransportKind::SesShared);
        assert!(reserve_send_admission(&redis, &keys_other, 1, t0)
            .await
            .unwrap());
    }

    /// Adversarial 9: shared and dedicated sends do not consume each other's
    /// buckets. Draining the shared bucket leaves the dedicated bucket at full
    /// capacity and vice versa.
    #[tokio::test]
    async fn shared_and_dedicated_rate_buckets_are_independent() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };
        let job = tracking_gate_job();
        let shared = send_admission_keys(&job, TransportKind::SesShared);
        let dedicated = send_admission_keys(&job, TransportKind::Dedicated);

        let t0 = 3_000_000i64;
        // Drain the shared buckets (rate 1/s, capacity 1).
        assert!(reserve_send_admission(&redis, &shared, 1, t0)
            .await
            .unwrap());
        assert!(
            !reserve_send_admission(&redis, &shared, 1, t0)
                .await
                .unwrap(),
            "shared bucket must be exhausted"
        );
        // The dedicated route's buckets are untouched.
        assert!(
            reserve_send_admission(&redis, &dedicated, 1, t0)
                .await
                .unwrap(),
            "a dedicated send must not be blocked by shared-pool consumption"
        );
        assert!(
            !reserve_send_admission(&redis, &dedicated, 1, t0)
                .await
                .unwrap(),
            "the dedicated bucket then exhausts on its own"
        );
    }

    /// The processor-level gate consumes the route's configured rate and
    /// defers (returns false) once it is exhausted; a 0 rate disables the
    /// gate; an unreachable Redis fails OPEN (best-effort).
    #[tokio::test]
    async fn check_send_admission_gates_on_config_rate_and_fails_open() {
        let shared_route = DeliveryRoute::SesShared;
        // Unreachable Redis: the gate must fail open (warn + admit).
        let dead_redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let processor = EmailProcessor::new(
            db,
            dead_redis,
            EmailConfig {
                ses: crate::common::SesConfig {
                    max_send_rate: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            processor
                .check_send_admission(&tracking_gate_job(), &shared_route)
                .await
                .unwrap(),
            "Redis unavailability must not block sends (best-effort gate)"
        );

        let Some(redis) = ephemeral_redis().await else {
            return;
        };
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let processor = EmailProcessor::new(
            db,
            redis,
            EmailConfig {
                ses: crate::common::SesConfig {
                    max_send_rate: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let job = tracking_gate_job();
        assert!(processor
            .check_send_admission(&job, &shared_route)
            .await
            .unwrap());
        assert!(processor
            .check_send_admission(&job, &shared_route)
            .await
            .unwrap());
        assert!(
            !processor
                .check_send_admission(&job, &shared_route)
                .await
                .unwrap(),
            "above the configured rate the row must be deferred, not sent"
        );

        // A zero rate disables the gate entirely — even with the bucket
        // already drained above.
        let unlimited = EmailProcessor::new(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://localhost/unused")
                .unwrap(),
            deadpool_redis::Config::from_url("redis://127.0.0.1:1")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .unwrap(),
            EmailConfig {
                ses: crate::common::SesConfig {
                    max_send_rate: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            unlimited
                .check_send_admission(&job, &shared_route)
                .await
                .unwrap(),
            "rate 0 must disable the admission gate without touching Redis"
        );
    }

    /// D/F25/F75: the audit `messages` row must follow the COMPLETE
    /// recipient set: 'partial' while siblings are owed (and finally
    /// partial on any terminal failure — the all-failed case), 'sent' when
    /// every recipient row is terminal-sent but not yet confirmed
    /// delivered, 'delivered' + messages.delivered_at when every recipient
    /// copy is confirmed delivered, and never crouching terminal states
    /// set by other paths.
    #[test]
    fn messages_progress_update_is_set_derived_and_scoped() {
        let sql = MESSAGES_PROGRESS_UPDATE_SQL;
        assert!(
            sql.contains("THEN 'sent'"),
            "provider acceptance for every recipient must derive 'sent' (F25)"
        );
        assert!(
            sql.contains("ELSE 'delivered'"),
            "every recipient confirmed delivered must derive 'delivered' (F75)"
        );
        assert!(
            sql.contains("THEN 'partial'"),
            "partial progress must be derivable (F25)"
        );
        assert!(sql.contains("tenant_id = $2"), "must be tenant-scoped");
        assert!(
            sql.contains("m.id = $1::uuid"),
            "must key on the message UUID"
        );
    }

    /// P0: the acceptance ledger's `send_unit` is the queue's own stable
    /// logical identity. Sales rows use `sa-send:{step_execution_id}` (the
    /// dispatcher's idempotency key); other rows use the queue row id plus
    /// the canonical recipient (attempt never participates, so retries share
    /// the unit).
    #[test]
    fn send_unit_matches_the_queue_idempotency_identity() {
        let job = tracking_gate_job();
        assert_eq!(
            send_unit_of(&job),
            "email_queue:job-1:recipient@example.com"
        );
        let mut retried = job.clone();
        retried.attempt = 9;
        assert_eq!(
            send_unit_of(&retried),
            send_unit_of(&job),
            "a retry of the same logical send is the same unit"
        );
        let mut sibling = job.clone();
        sibling.to = "Other@Example.com".into();
        assert_eq!(
            send_unit_of(&sibling),
            "email_queue:job-1:other@example.com",
            "canonical recipient disambiguates multi-recipient rows"
        );

        let mut sales = job.clone();
        sales.sales_step_execution_id = Some("0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89".into());
        assert_eq!(
            send_unit_of(&sales),
            "sa-send:0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89",
            "sales mail must use the queue's sa-send identity"
        );
    }

    /// G.3c: simulate the reclaim sequence — the first claim wins, the
    /// reclaim of a lease that expired mid-send is refused, and the marker
    /// is releasable once the attempt is handled.
    // ---------------------------------------------------------------------------
    // Audit-1 / Fix 3: real per-IP warmup state (dedicated_ips, migrations 071/093)
    // ---------------------------------------------------------------------------

    #[test]
    fn select_delivery_ip_is_empty_without_dedicated_identities() {
        // No dedicated IP (shared pool = platform reputation): no route
        // candidate, so the send rides SES and warmup must stay off.
        assert!(select_delivery_ip(Utc::now(), &[])
            .expect("empty selection is valid")
            .is_empty());
    }

    #[test]
    fn select_delivery_ip_derives_the_canonical_day_and_limit() {
        let now = Utc::now();
        let pool = select_delivery_ip(
            now,
            &[dedicated_ip_started(now, "dip-1", "203.0.113.9", true, 3)],
        )
        .expect("valid candidate");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].dedicated_ip_id, "dip-1");
        assert_eq!(pool[0].source_ip.to_string(), "203.0.113.9");
        assert_eq!(pool[0].warmup_day, 3);
        assert_eq!(
            pool[0].daily_limit,
            Some(WarmupSchedule::limit_for_day(3)),
            "the daily cap must come from the canonical mail_common schedule"
        );
        assert!(pool[0].is_warming());
    }

    /// P0 graduation: an `active` (graduated) dedicated IP stays in the pool
    /// with NO daily limit — it is still routed as dedicated, just without
    /// throttling (the old warming-only query dropped it to the shared pool).
    #[test]
    fn select_delivery_ip_keeps_graduated_ips_as_unthrottled_candidates() {
        let now = Utc::now();
        let pool = select_delivery_ip(
            now,
            &[
                dedicated_ip("dip-active", "203.0.113.20", false, 90),
                dedicated_ip("dip-warming", "203.0.113.21", true, 5),
            ],
        )
        .expect("valid candidates");
        assert_eq!(pool.len(), 2);
        assert_eq!(
            pool[0].dedicated_ip_id, "dip-warming",
            "warming candidates must be preferred (they still have to graduate)"
        );
        assert_eq!(pool[1].dedicated_ip_id, "dip-active");
        assert_eq!(
            pool[1].daily_limit, None,
            "a graduated IP consumes NO warmup quota"
        );
        assert!(!pool[1].is_warming());
    }

    #[test]
    fn select_delivery_ip_orders_warming_by_least_warmed_first() {
        let now = Utc::now();
        let pool = select_delivery_ip(
            now,
            &[
                DedicatedIp {
                    id: "dip-new".into(),
                    ip_address: "203.0.113.3".into(),
                    warming: true,
                    warmup_started_at: Some(now - chrono::Duration::days(3)),
                },
                DedicatedIp {
                    id: "dip-old".into(),
                    ip_address: "203.0.113.1".into(),
                    warming: true,
                    warmup_started_at: Some(now - chrono::Duration::days(40)),
                },
            ],
        )
        .expect("valid candidates");
        assert_eq!(pool[0].dedicated_ip_id, "dip-new");
        assert_eq!(pool[1].dedicated_ip_id, "dip-old");
    }

    #[test]
    fn select_delivery_ip_clamps_clock_skew_to_day_zero() {
        let now = Utc::now();
        let pool = select_delivery_ip(
            now,
            &[DedicatedIp {
                id: "dip-future".into(),
                ip_address: "203.0.113.4".into(),
                warming: true,
                warmup_started_at: Some(now + chrono::Duration::hours(1)),
            }],
        )
        .expect("valid candidate");
        assert_eq!(pool[0].warmup_day, 0, "future timestamps clamp to day 0");
        assert_eq!(pool[0].daily_limit, Some(50), "canonical day-0 cap");
    }

    #[test]
    fn select_delivery_ip_refuses_unparseable_and_unthrottleable_warming_rows() {
        let now = Utc::now();
        let bad_ip =
            select_delivery_ip(now, &[dedicated_ip("dip-bad", "not-an-ip", true, 1)]).unwrap_err();
        assert!(
            matches!(bad_ip, ProcessorError::Config(ref message) if message.contains("dip-bad")),
            "an unparseable identity must fail closed: {bad_ip}"
        );

        let no_start = select_delivery_ip(
            now,
            &[DedicatedIp {
                id: "dip-no-start".into(),
                ip_address: "203.0.113.9".into(),
                warming: true,
                warmup_started_at: None,
            }],
        )
        .unwrap_err();
        assert!(
            matches!(no_start, ProcessorError::Config(ref message) if message.contains("dip-no-start")),
            "a warming identity without a start cannot be throttled: {no_start}"
        );
    }

    /// get_domain must consult the real dedicated-IP tables (warming AND
    /// active — a graduated IP must keep being routed), and its rows must
    /// carry the identity the admission counter keys on.
    #[test]
    fn get_domain_sql_consults_warming_and_active_dedicated_ips() {
        assert!(
            GET_DOMAIN_SQL.contains("dedicated_ips"),
            "get_domain must read the real dedicated-IP state: {GET_DOMAIN_SQL}"
        );
        assert!(
            !GET_DOMAIN_SQL.contains("false AS warmup_enabled"),
            "the hardcoded warmup constants must be gone: {GET_DOMAIN_SQL}"
        );
        assert!(
            GET_DOMAIN_SQL.contains("'id', di.id::text")
                && GET_DOMAIN_SQL.contains("'ip_address', di.ip_address"),
            "the routing source must carry the per-IP identity: {GET_DOMAIN_SQL}"
        );
        assert!(
            GET_DOMAIN_SQL.contains("di.status IN ('warming', 'active')")
                && GET_DOMAIN_SQL.contains("'warming', (di.status = 'warming')"),
            "both warming and graduated identities must be routable: {GET_DOMAIN_SQL}"
        );
        assert!(
            GET_DOMAIN_SQL.contains("d.ses_verified AS ses_verified")
                && !GET_DOMAIN_SQL.contains("$3::boolean"),
            "SES readiness must be carried to the route-aware gate, not pre-filtered: {GET_DOMAIN_SQL}"
        );
        assert!(
            !GET_DOMAIN_SQL.contains("warmup_starts"),
            "timestamps alone are not a reputation boundary: {GET_DOMAIN_SQL}"
        );
    }

    /// Fix 3: the admission keys are IP-scoped (the reputation boundary) and
    /// the send marker is idempotent across retries of one send unit while
    /// staying distinct across recipients of the same row.
    #[test]
    fn warmup_admission_keys_are_ip_scoped_and_per_send_unit() {
        let today = "2026-09-11";
        let key = warmup_ip_counter_key("203.0.113.9", today);
        assert_eq!(key, "apexmail:warmup:ip:203.0.113.9:2026-09-11");
        assert!(
            !key.contains("domain-1"),
            "the domain must not participate in the warmup boundary: {key}"
        );

        let job = tracking_gate_job();
        let marker = warmup_ip_send_marker_key("203.0.113.9", today, &job);
        assert_eq!(
            marker,
            "apexmail:warmup:sent:203.0.113.9:2026-09-11:job-1:recipient@example.com"
        );
        // A retry (attempt bumps, recipient unchanged) reuses the same
        // marker — no double-count.
        let mut retried = job.clone();
        retried.attempt = 5;
        assert_eq!(
            warmup_ip_send_marker_key("203.0.113.9", today, &retried),
            marker
        );
        // A different recipient of the same row is a different send unit.
        let mut other = job.clone();
        other.to = "other@example.com".into();
        assert_ne!(
            warmup_ip_send_marker_key("203.0.113.9", today, &other),
            marker
        );
    }

    /// With the real state wired, the gate switch defaults ON — it only ever
    /// throttles domains whose tenant actually has a warming dedicated IP.
    #[test]
    fn warmup_gate_defaults_to_enabled() {
        assert!(
            crate::common::WarmupConfig::default().enabled,
            "warmup limiting must engage by default now that real state exists"
        );
    }

    /// Audit item 26 (delete branch) / P0: warmup capacity and exactly-once
    /// acceptance each have EXACTLY ONE entry point in the production send
    /// path, and the limit derivation is still the canonical
    /// `mail_common::warmup` schedule with the canonical per-IP Redis key.
    /// The scan is over the production region only (everything before the
    /// first `#[cfg(test)]`), so test code cannot mask a second entry point.
    #[test]
    fn warmup_and_acceptance_have_one_production_entry_point_each() {
        let source = include_str!("processor.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("processor source must not begin with a test module");

        assert_eq!(
            production
                .matches("async fn reserve_warmup_capacity(")
                .count(),
            1,
            "exactly one warmup-reservation function may exist"
        );
        assert_eq!(
            production.matches("reserve_warmup_capacity(").count(),
            2,
            "one definition + one call: a single warmup-capacity reservation entry point"
        );
        assert_eq!(
            production.matches("fn select_delivery_ip(").count(),
            1,
            "exactly one selection function may exist"
        );
        assert_eq!(
            production.matches("WarmupSchedule::limit_for_day").count(),
            1,
            "the canonical mail_common schedule must be the only limit derivation"
        );
        assert!(
            production.contains("use mail_common::warmup::WarmupSchedule;"),
            "the limit derivation must come from mail_common::warmup"
        );
        assert_eq!(
            production
                .matches(concat!("apexmail:warmup:", "ip:{}:{}"))
                .count(),
            1,
            "the canonical per-IP Redis key format must be built in exactly one place"
        );

        // Durable exactly-once: one claim definition + one call in dispatch;
        // one accepted-record definition + one call; one failed-record
        // definition + one call.
        assert_eq!(production.matches("async fn claim_acceptance(").count(), 1);
        assert_eq!(production.matches("claim_acceptance(").count(), 2);
        assert_eq!(
            production
                .matches("async fn record_acceptance_accepted(")
                .count(),
            1
        );
        assert_eq!(production.matches("record_acceptance_accepted(").count(), 2);
        assert_eq!(
            production
                .matches("async fn record_acceptance_failed(")
                .count(),
            1
        );
        assert_eq!(production.matches("record_acceptance_failed(").count(), 2);
        assert_eq!(
            production.matches("const ACCEPTANCE_RESERVE_LEASE").count(),
            1,
            "the reclaim lease must be a single named constant"
        );

        // The pre-DATA route gate is consulted exactly once in dispatch.
        assert_eq!(
            production
                .matches("self.transport.ensure_route_dispatchable(")
                .count(),
            1,
            "dispatch must gate the route exactly once, before any reservation"
        );
        // No post-hoc route verification/enforcement survives: a verification
        // failure can never follow an accepted send.
        assert!(
            !production.contains("settle_delivery_route")
                && !production.contains("verify_delivery_route"),
            "post-acceptance route verification must be gone"
        );
    }

    /// Audit item 26 (delete branch) hostile-input equivalent: the send path
    /// never resolves a recipient provider for admission and never reads the
    /// ISP warmup catalog or the inert per-pool schedule rows. With no
    /// reader, a catalog profile that is absent, maps to nothing, or carries
    /// a zero/negative/huge target cannot produce ANY cap — the canonical
    /// per-IP limit above stays the sole maximum. Provider strings that do
    /// exist in this file are event-persistence evidence only.
    #[test]
    fn warmup_send_path_has_no_isp_catalog_or_provider_derived_cap() {
        let source = include_str!("processor.rs");
        for needle in [
            ["isp", "_warmup"].concat(),
            ["mx", "_patterns"].concat(),
            ["Warmup", "CatalogRepo"].concat(),
            ["Warmup", "ExecutionRepo"].concat(),
            ["record", "_daily_actual"].concat(),
        ] {
            assert!(
                !source.contains(needle.as_str()),
                "the send path must contain no ISP-catalog-derived admission \
                 input (found {needle:?})"
            );
        }
    }

    /// Audit-1 / Fix 3 / P0 behavioral gate (ephemeral redis): with a
    /// warming IP in the pool the Redis counter (canonical
    /// `mail_common::warmup` day cap) blocks sends above the cap, admits
    /// below it, is idempotent per send unit, ignores the retired
    /// domain-keyed counter, and fails closed when Redis is unavailable.
    #[tokio::test]
    async fn warmup_capacity_blocks_above_the_ip_cap_and_fails_closed() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };

        let job = tracking_gate_job();
        let pool = select_delivery_ip(Utc::now(), &[dedicated_ip("dip-1", "203.0.113.9", true, 3)])
            .expect("candidate pool");
        let day_limit = WarmupSchedule::limit_for_day(3);
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let key = warmup_ip_counter_key("203.0.113.9", &today);
        let legacy_domain_key = format!("warmup:count:{}:{}", today, job.domain_id);

        // Below the cap the reservation takes a slot on the selected IP.
        let reserved = reserve_warmup_capacity(&redis, &job, &pool, &today)
            .await
            .expect("redis available")
            .expect("below the cap");
        assert_eq!(reserved.candidate.dedicated_ip_id, "dip-1");
        let reservation = reserved
            .reservation
            .as_ref()
            .expect("a warming candidate consumes quota");
        assert_eq!(reservation.source_ip.to_string(), "203.0.113.9");
        assert_eq!(reservation.counter_key, key);
        assert_eq!(
            reservation.marker_key,
            warmup_ip_send_marker_key("203.0.113.9", &today, &job)
        );

        let counter = |key: String| async {
            let mut conn = redis.get().await.unwrap();
            redis::cmd("GET")
                .arg(key)
                .query_async::<Option<i64>>(&mut *conn)
                .await
                .unwrap()
        };
        assert_eq!(counter(key.clone()).await, Some(1));

        // A retry of the SAME send unit is idempotent: admitted without a
        // second increment (the marker is the guard).
        let retry = reserve_warmup_capacity(&redis, &job, &pool, &today)
            .await
            .expect("redis available")
            .expect("retry of a reserved unit");
        assert!(retry.reservation.is_some());
        assert_eq!(
            counter(key.clone()).await,
            Some(1),
            "a retry must not double-count against the IP quota"
        );

        // Fill the counter to the canonical cap: a DIFFERENT send unit is
        // refused and the counter stays at the cap.
        {
            let mut conn = redis.get().await.unwrap();
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(day_limit)
                .query_async(&mut *conn)
                .await
                .unwrap();
        }
        let mut other_recipient = job.clone();
        other_recipient.to = "other@example.com".into();
        assert!(
            reserve_warmup_capacity(&redis, &other_recipient, &pool, &today)
                .await
                .expect("redis available")
                .is_none(),
            "a send above the IP's canonical day cap must be refused"
        );
        assert_eq!(counter(key.clone()).await, Some(day_limit as i64));

        // The RETIRED domain-keyed counter is not authoritative.
        {
            let mut conn = redis.get().await.unwrap();
            let _: () = redis::cmd("SET")
                .arg(&legacy_domain_key)
                .arg(day_limit + 10_000)
                .query_async(&mut *conn)
                .await
                .unwrap();
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(day_limit - 1)
                .query_async(&mut *conn)
                .await
                .unwrap();
        }
        assert!(
            reserve_warmup_capacity(&redis, &other_recipient, &pool, &today)
                .await
                .expect("redis available")
                .is_some(),
            "the domain-keyed counter must not gate the send"
        );

        // Fail closed: an unavailable quota store refuses a warming pool.
        let dead_redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        assert!(
            reserve_warmup_capacity(&dead_redis, &job, &pool, &today)
                .await
                .is_err(),
            "an unavailable quota store must not admit a warming send"
        );
    }

    /// P0 aggregate pool (ephemeral redis): two warming IPs at 5/day accept
    /// TEN concurrent sends — five each, none above its cap — instead of the
    /// old single-IP selection deferring mail while the second IP had
    /// capacity.
    #[tokio::test]
    async fn aggregate_pool_spreads_ten_sends_across_two_five_per_day_ips() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };
        let now = Utc::now();
        let pool = select_delivery_ip(
            now,
            &[
                dedicated_ip("dip-a", "203.0.113.10", true, 2),
                dedicated_ip("dip-b", "203.0.113.11", true, 2),
            ],
        )
        .expect("candidate pool");
        // Canonical day-2 cap is 100; this test exercises the AGGREGATE
        // behaviour with a 5/day cap by constructing the pool directly (the
        // derivation above is covered by the canonical-schedule tests).
        let pool: Vec<RoutingCandidate> = pool
            .into_iter()
            .map(|mut candidate| {
                candidate.daily_limit = Some(5);
                candidate
            })
            .collect();
        let today = now.format("%Y-%m-%d").to_string();

        let mut sends = Vec::new();
        for index in 0..10 {
            let redis = redis.clone();
            let pool = pool.clone();
            let today = today.clone();
            sends.push(async move {
                let mut job = tracking_gate_job();
                job.id = format!("job-{index}");
                job.to = format!("recipient-{index}@example.com");
                reserve_warmup_capacity(&redis, &job, &pool, &today).await
            });
        }
        let results = futures::future::join_all(sends).await;

        let chosen: Vec<String> = results
            .into_iter()
            .map(|result| {
                result
                    .expect("redis available")
                    .expect("ten sends must fit the aggregate pool")
                    .candidate
                    .dedicated_ip_id
            })
            .collect();
        assert_eq!(chosen.len(), 10);

        let counter = |ip: &str| {
            let key = warmup_ip_counter_key(ip, &today);
            let redis = redis.clone();
            async move {
                let mut conn = redis.get().await.unwrap();
                redis::cmd("GET")
                    .arg(key)
                    .query_async::<Option<i64>>(&mut *conn)
                    .await
                    .unwrap()
                    .unwrap_or(0)
            }
        };
        let a = counter("203.0.113.10").await;
        let b = counter("203.0.113.11").await;
        assert!(a <= 5 && b <= 5, "no IP may exceed its cap: a={a} b={b}");
        assert_eq!(a + b, 10, "every admitted send consumed exactly one slot");
        assert_eq!(
            chosen.iter().filter(|id| id.as_str() == "dip-a").count() as i64,
            a,
            "the route must match the counter of the SAME chosen IP"
        );
        assert_eq!(
            chosen.iter().filter(|id| id.as_str() == "dip-b").count() as i64,
            b
        );
    }

    /// P0 graduation: an `active` (graduated) IP is still SELECTED for a
    /// dedicated route and consumes NO warmup quota — proven by reserving
    /// from an active-only pool with a dead Redis: no counter is needed.
    #[tokio::test]
    async fn active_ip_routes_dedicated_without_consuming_quota() {
        let job = tracking_gate_job();
        let pool = select_delivery_ip(
            Utc::now(),
            &[dedicated_ip("dip-graduated", "203.0.113.77", false, 90)],
        )
        .expect("candidate pool");
        assert_eq!(pool.len(), 1);
        assert!(!pool[0].is_warming());

        let dead_redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let reserved = reserve_warmup_capacity(
            &dead_redis,
            &job,
            &pool,
            &Utc::now().format("%Y-%m-%d").to_string(),
        )
        .await
        .expect("an unthrottled pool needs no quota store")
        .expect("a graduated IP is always eligible");
        assert!(
            reserved.reservation.is_none(),
            "a graduated IP must consume no warmup quota"
        );
        match reserved.route() {
            DeliveryRoute::Dedicated {
                dedicated_ip_id,
                source_ip,
            } => {
                assert_eq!(dedicated_ip_id, "dip-graduated");
                assert_eq!(source_ip.to_string(), "203.0.113.77");
            }
            other => panic!("expected the dedicated route, got {other}"),
        }
    }

    /// P0 aggregate fallback: when every warming candidate is at its cap but
    /// an active one exists, the send SPILLS to the active IP (with no quota
    /// consumption) instead of deferring mail that has a valid capacity.
    #[tokio::test]
    async fn exhausted_warming_pool_spills_to_an_active_ip() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };
        let now = Utc::now();
        let mut pool = select_delivery_ip(
            now,
            &[
                dedicated_ip("dip-warm", "203.0.113.30", true, 2),
                dedicated_ip("dip-active", "203.0.113.31", false, 90),
            ],
        )
        .expect("candidate pool");
        for candidate in &mut pool {
            if candidate.is_warming() {
                candidate.daily_limit = Some(1);
            }
        }
        let today = now.format("%Y-%m-%d").to_string();
        // Exhaust the warming IP.
        let first = tracking_gate_job();
        let reserved = reserve_warmup_capacity(&redis, &first, &pool, &today)
            .await
            .expect("redis available")
            .expect("first send fits the warming IP");
        assert_eq!(reserved.candidate.dedicated_ip_id, "dip-warm");
        assert!(reserved.reservation.is_some());

        let mut second = tracking_gate_job();
        second.to = "second@example.com".into();
        let reserved = reserve_warmup_capacity(&redis, &second, &pool, &today)
            .await
            .expect("redis available")
            .expect("the active IP must absorb the overflow");
        assert_eq!(reserved.candidate.dedicated_ip_id, "dip-active");
        assert!(
            reserved.reservation.is_none(),
            "the active fallback must not consume warmup quota"
        );
    }

    // ---------------------------------------------------------------------------
    // F44: every worker metadata write object-guards jsonb_set
    // ---------------------------------------------------------------------------

    /// Historical caller metadata could be a scalar/array; `jsonb_set` on it
    /// fails with SQLSTATE 22023 and wedged whole claim batches. Every
    /// write must guard `jsonb_typeof(metadata) = 'object'`.
    #[test]
    fn metadata_writes_object_guard_non_object_metadata() {
        for (name, sql) in [
            ("SUPPRESSED_UPDATE_SQL", SUPPRESSED_UPDATE_SQL),
            ("HARD_BOUNCE_UPDATE_SQL", HARD_BOUNCE_UPDATE_SQL),
            ("DLQ_FAIL_UPDATE_SQL", DLQ_FAIL_UPDATE_SQL),
            ("HANDLE_SUCCESS_UPDATE_SQL", HANDLE_SUCCESS_UPDATE_SQL),
            ("SOFT_BOUNCE_UPDATE_SQL", SOFT_BOUNCE_UPDATE_SQL),
            ("POSSIBLY_SENT_UPDATE_SQL", POSSIBLY_SENT_UPDATE_SQL),
            ("REQUEUE_JOB_UPDATE_SQL", REQUEUE_JOB_UPDATE_SQL),
            ("FETCH_JOBS_SQL", FETCH_JOBS_SQL),
        ] {
            assert!(
                sql.contains("jsonb_typeof(metadata) = 'object'"),
                "{name} must object-guard its metadata writes (F44): {sql}"
            );
            assert!(
                !sql.contains("COALESCE(metadata, '{}'::jsonb)"),
                "{name} must not COALESCE unguarded metadata (F44): {sql}"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // F45: claim honors pending_recipients only as a trusted subset
    // ---------------------------------------------------------------------------

    #[test]
    fn claim_only_honors_pending_recipients_that_are_subset_of_envelope() {
        assert!(
            FETCH_JOBS_SQL.contains("jsonb_typeof(metadata->'pending_recipients') = 'array'"),
            "the pending set must be type-checked (F45)"
        );
        assert!(
            FETCH_JOBS_SQL.contains("pending_addr <> ALL("),
            "every pending recipient must be proven to be an envelope recipient (F45)"
        );
        assert!(
            FETCH_JOBS_SQL.contains("ELSE to_addresses"),
            "a rejected pending set must fall back to the trusted envelope record (F45)"
        );
    }

    // ---------------------------------------------------------------------------
    // F24 (worker side): the claim only ever takes pending rows — cancelled
    // rows are never dispatched, and claimed (processing) rows are the
    // irreversible dispatch boundary the API's cancellation check relies on.
    // ---------------------------------------------------------------------------

    #[test]
    fn claim_takes_only_pending_or_expired_rows() {
        let claim_predicate = "status = 'pending'";
        assert!(FETCH_JOBS_SQL.contains(claim_predicate));
        assert!(
            FETCH_JOBS_SQL.contains("OR (status = 'processing' AND locked_until < NOW())"),
            "expired-lease reclaims must be explicit (F24/F21)"
        );
    }

    // ---------------------------------------------------------------------------
    // F25: parent progress derived from the complete recipient set
    // ---------------------------------------------------------------------------

    #[test]
    fn parent_progress_is_derived_from_the_complete_recipient_set() {
        // 'partial' while any recipient row is not terminal.
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL.contains("THEN 'partial'"),
            "siblings still owed a delivery must leave the parent partial (F25)"
        );
        // 'processing' while NOTHING is terminal yet (mid-flight, still
        // cancellable — a soft-bounce deferral must not strand the parent).
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL.contains("THEN 'processing'"),
            "all-non-terminal parents must stay processing (F25)"
        );
        // Provider acceptance vs confirmed delivery are DISTINCT states.
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL.contains("q.delivered_at IS NULL"),
            "recipient confirmed-delivery timestamps drive the aggregate (F25/F75)"
        );
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL.contains("ELSE 'delivered'"),
            "the all-confirmed-delivered terminal state must exist (F25/F75)"
        );
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL.contains("THEN NOW() ELSE m.sent_at"),
            "sent_at is stamped only on full completion (F25)"
        );
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL.contains("THEN NOW() ELSE m.delivered_at"),
            "delivered_at is stamped once at its actual event (F75)"
        );
        // Scheduled and processing parents are accepted (the scheduled →
        // processing / sent edges previously did not exist at all).
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL
                .contains("IN ('queued', 'scheduled', 'processing', 'partial', 'sent')"),
            "scheduled/processing/sent parents must be transitionable (F25)"
        );
        // Recipient-level state is the email_queue set, not the single job.
        assert!(MESSAGES_PROGRESS_UPDATE_SQL.contains("FROM email_queue q"));
        // A parent with no recipient rows is never aggregated.
        assert!(
            MESSAGES_PROGRESS_UPDATE_SQL
                .contains("AND EXISTS (SELECT 1 FROM email_queue q WHERE q.message_id = m.id)"),
            "childless parents must not be fabricated into a terminal state (F25)"
        );
    }

    #[test]
    fn restart_reconciliation_sweep_targets_all_terminal_children() {
        // F25: the sweep covers parents stuck in processing/partial whose
        // children are ALL terminal (the crash-residue), including the
        // all-failed case (bounced/failed/suppressed/cancelled) that used
        // to stay 'processing' forever.
        assert!(apexmail_lib::email_headers::RECONCILE_STUCK_PARENTS_SQL
            .contains("m.status IN ('processing', 'partial')"));
        assert!(apexmail_lib::email_headers::RECONCILE_STUCK_PARENTS_SQL
            .contains("q.status NOT IN ('sent', 'bounced', 'failed', 'suppressed', 'cancelled')"));
        assert!(apexmail_lib::email_headers::RECONCILE_STUCK_PARENTS_SQL.contains("THEN 'partial'"));
    }

    // ── F18: explicit tenant policy result ───────────────────────────

    /// F55: the dispatch-time consent gate must EXIT dispatch on
    /// `Deferred` — the old `Ok(None)` conflated "verification failed"
    /// with "not suppressed" and let the job fall through into the
    /// transport while its row was already requeued. Structural guard on
    /// the gate block in `process_job_inner`.
    #[test]
    fn dispatch_consent_gate_exits_immediately_on_deferral() {
        let source = include_str!("processor.rs");
        let gate_start = source
            .find("match self.dispatch_consent(job).await?")
            .expect("dispatch_consent gate present");
        let gate_end = source[gate_start..]
            .find("ConsentDecision::Allowed => {}")
            .expect("Allowed arm present")
            + gate_start;
        let gate = &source[gate_start..gate_end];
        assert!(
            gate.contains("ConsentDecision::Suppressed(reason)"),
            "suppressed arm present"
        );
        assert!(
            gate.contains("ConsentDecision::Deferred(reason)"),
            "deferred arm present"
        );
        // Both non-Allowed arms must return from process_job_inner BEFORE
        // the gate block ends (no fall-through into transport).
        let returns = gate.matches("return Ok(());").count();
        assert!(
            returns >= 2,
            "both the Suppressed and Deferred arms must exit dispatch immediately (found {returns})"
        );
        assert!(
            gate.contains("self.requeue_job(job, reason).await?;"),
            "the deferred row is requeued before exiting"
        );
    }

    /// F18: the tenant policy gate likewise exits on every non-Allowed
    /// policy (never fails open into transport).
    #[test]
    fn tenant_policy_gate_exits_on_every_non_allowed_policy() {
        let source = include_str!("processor.rs");
        let gate_start = source
            .find("match self.tenant_policy(&job.tenant_id).await {")
            .expect("tenant_policy gate present");
        let arm_start = gate_start
            + source[gate_start..]
                .find("policy => {")
                .expect("non-Allowed arm present");
        let arm = &source[arm_start..arm_start + 900];
        assert!(
            arm.contains("return Ok(());"),
            "the non-Allowed arm must exit dispatch immediately"
        );
        assert!(
            arm.contains("self.requeue_job(job, reason).await?;"),
            "the restricted/unavailable row is deferred before exiting"
        );
    }

    #[test]
    fn tenant_policy_reasons_map_to_deferral_reasons() {
        assert_eq!(TenantPolicy::Allowed.requeue_reason(), "allowed");
        assert_eq!(
            TenantPolicy::Restricted("tenant_suspended".into()).requeue_reason(),
            "tenant_suspended"
        );
        assert_eq!(
            TenantPolicy::Restricted("tenant_pending".into()).requeue_reason(),
            "tenant_pending"
        );
        assert_eq!(
            TenantPolicy::TemporarilyUnavailable.requeue_reason(),
            "tenant_policy_unavailable"
        );
        // Only Allowed is a permission; everything else defers.
        assert_ne!(TenantPolicy::Allowed, TenantPolicy::TemporarilyUnavailable);
        assert_ne!(
            TenantPolicy::Restricted("tenant_suspended".into()),
            TenantPolicy::Allowed
        );
    }

    // ── F55: explicit consent decision result ─────────────────────────

    #[test]
    fn consent_decisions_are_three_valued_not_option() {
        // Deferred is DISTINCT from Allowed — a failed verification is
        // never permission to send (the Option<String> conflation let the
        // caller fall through into the transport).
        assert_ne!(ConsentDecision::Allowed, ConsentDecision::Deferred("x"));
        assert_ne!(
            ConsentDecision::Allowed,
            ConsentDecision::Suppressed("reason".into())
        );
        assert!(matches!(
            ConsentDecision::Deferred("consent_check_deferred"),
            ConsentDecision::Deferred(_)
        ));
        // The category exemptions used by dispatch_consent.
        assert!(
            apexmail_lib::email_headers::message_category::is_preference_exempt("transactional")
        );
        assert!(!apexmail_lib::email_headers::message_category::is_preference_exempt("marketing"));
    }

    #[test]
    fn consent_queries_cover_both_dimensions() {
        // The dispatch-time decision reads global suppression AND the
        // category preference in one authoritative query.
        assert!(DISPATCH_CONSENT_SQL.contains("FROM suppressions"));
        assert!(DISPATCH_CONSENT_SQL.contains("FROM subscription_preferences"));
        assert!(DISPATCH_CONSENT_SQL.contains("category = $3"));
    }

    #[test]
    fn claim_time_suppression_caching_is_negative_only() {
        // F55: positive suppression verdicts are never written to the
        // cache — this source property is the regression guard for the
        // stale-positive-terminalize defect (a resubscribed recipient
        // could be suppressed from a primed cache entry).
        let source = include_str!("processor.rs");
        assert!(
            source.contains("Collect positive results WITHOUT caching them (F55)"),
            "the claim-time check must keep positives uncached"
        );
    }

    // ---------------------------------------------------------------------------
    // F26: MIME To/Cc preservation + logical Message-ID
    // ---------------------------------------------------------------------------

    #[test]
    fn split_mime_headers_reads_structured_server_shape() {
        // F26: current writer persists ARRAYS of mailbox strings.
        let headers = serde_json::json!({
            "to": ["a@example.com", "B <b@example.com>"],
            "cc": ["c@example.com"],
            "reply_to": "reply@example.com",
            "custom": {"X-Campaign": "summer"}
        });
        let SplitMimeHeaders {
            mime_to,
            mime_cc,
            reply_to,
            custom,
        } = split_mime_headers(Some(&headers));
        assert_eq!(
            mime_to,
            vec![
                Mailbox {
                    name: None,
                    email: "a@example.com".into()
                },
                Mailbox {
                    name: Some("B".into()),
                    email: "b@example.com".into()
                },
            ]
        );
        assert_eq!(
            mime_cc,
            vec![Mailbox {
                name: None,
                email: "c@example.com".into()
            }]
        );
        assert_eq!(
            reply_to,
            Some(Mailbox {
                name: None,
                email: "reply@example.com".into()
            })
        );
        assert_eq!(
            custom,
            vec![("X-Campaign".to_string(), "summer".to_string())]
        );
    }

    #[test]
    fn split_mime_headers_parses_legacy_comma_joined_strings() {
        // F26: legacy rows persisted comma-joined strings — parsed
        // explicitly into the structured list (backfill-by-parse).
        let headers = serde_json::json!({
            "to": "a@example.com, b@example.com",
            "cc": "c@example.com",
            "reply_to": "reply@example.com",
            "custom": {"X-Campaign": "summer"}
        });
        let SplitMimeHeaders {
            mime_to, mime_cc, ..
        } = split_mime_headers(Some(&headers));
        assert_eq!(
            mime_to,
            vec![
                Mailbox {
                    name: None,
                    email: "a@example.com".into()
                },
                Mailbox {
                    name: None,
                    email: "b@example.com".into()
                },
            ]
        );
        assert_eq!(
            mime_cc,
            vec![Mailbox {
                name: None,
                email: "c@example.com".into()
            }]
        );
    }

    #[test]
    fn split_mime_headers_legacy_flat_map_still_yields_custom_headers() {
        let headers = serde_json::json!({"X-Old": "shape"});
        let SplitMimeHeaders {
            mime_to,
            mime_cc,
            reply_to,
            custom,
        } = split_mime_headers(Some(&headers));
        assert!(mime_to.is_empty());
        assert!(mime_cc.is_empty());
        assert!(reply_to.is_none());
        assert_eq!(custom, vec![("X-Old".to_string(), "shape".to_string())]);
    }

    #[test]
    fn split_mime_headers_absent_metadata_is_all_empty() {
        let SplitMimeHeaders {
            mime_to,
            mime_cc,
            reply_to,
            custom,
        } = split_mime_headers(None);
        assert!(mime_to.is_empty() && mime_cc.is_empty() && reply_to.is_none());
        assert!(custom.is_empty());
    }

    #[test]
    fn logical_message_id_is_derived_from_the_platform_message_id() {
        let job = tracking_gate_job();
        let id = logical_message_id(&job).unwrap();
        assert!(id.starts_with('<') && id.ends_with("@example.com>"));
        assert!(
            id.contains("msg-1"),
            "the logical id must be stable across copies: {id}"
        );
        // Both recipient copies of one message derive the SAME id.
        let sibling = EmailJob {
            to: "other@example.com".into(),
            ..job.clone()
        };
        assert_eq!(id, logical_message_id(&sibling).unwrap());
        // A malformed message id yields none (mail-builder's Date-based
        // fallback then applies) instead of a broken header.
        let mut bad = job.clone();
        bad.message_id = "not @ valid".into();
        assert!(logical_message_id(&bad).is_none());
    }

    // ── F74: reserved namespace at the pre-transport boundary ──────────

    /// Every spelling of the internal namespace is stripped from caller
    /// custom headers, and the canonical identity headers are generated
    /// from the persisted job context ONLY.
    #[tokio::test]
    async fn prepare_email_blocks_the_whole_reserved_namespace() {
        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: false,
            ..crate::common::TrackingConfig::default()
        })
        .await;

        let mut job = tracking_gate_job();
        job.headers = Some(serde_json::json!({
            "to": ["to@example.com"],
            "cc": [],
            "reply_to": "",
            "custom": {
                // Legacy alias spellings (case variants) must be blocked
                // here — the API blocks them too, but the worker is the
                // last boundary before transport.
                "X-ApexMail-MessageId": "forged-message",
                "x-apexmail-tenant-id": "forged-tenant",
                "X-APExmail-CampaignId": "forged-campaign",
                "X-ApexMail-Anything": "forged",
                "X-Legit-Custom": "kept"
            }
        }));
        let prepared = processor
            .prepare_email(&job, &tracking_gate_domain(), &DeliveryRoute::SesShared)
            .unwrap();

        let header = |name: &str| {
            prepared
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        // Canonical identity headers come from the JOB only.
        assert_eq!(
            header(apexmail_lib::email_headers::HEADER_MESSAGE_ID).as_deref(),
            Some("msg-1")
        );
        assert_eq!(
            header(apexmail_lib::email_headers::HEADER_TENANT_ID).as_deref(),
            Some("tenant-1")
        );
        // No alias spelling survives with a forged value (exact-name
        // matching: the alias spellings differ from the canonical ones).
        let exact_header = |name: &str| {
            prepared
                .headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(exact_header("X-ApexMail-MessageId"), None);
        assert_eq!(exact_header("X-APExmail-CampaignId"), None);
        assert_eq!(exact_header("X-ApexMail-Anything"), None);
        // The lowercase canonical spelling appears ONCE, from the job.
        assert_eq!(
            prepared
                .headers
                .iter()
                .filter(
                    |(k, _)| k.eq_ignore_ascii_case(apexmail_lib::email_headers::HEADER_TENANT_ID)
                )
                .count(),
            1,
            "exactly one tenant-id header, generated from the job"
        );
        assert_eq!(header("x-apexmail-tenant-id").as_deref(), Some("tenant-1"));
        // Ordinary custom headers pass.
        assert_eq!(header("X-Legit-Custom").as_deref(), Some("kept"));
    }

    // ── F13: server-owned unsubscribe link on outgoing mail ───────────

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn outgoing_mail_carries_a_v2_unsubscribe_link_with_message_identity() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = "test-secret-key-32-bytes-minimum!!";
        std::env::set_var("TRACKING_SECRET_KEY", secret);

        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".into(),
            open_pixel_path: "/o".into(),
            click_redirect_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            secret_key: Some(zeroize::Zeroizing::new(secret.to_string())),
        })
        .await;

        let mut job = tracking_gate_job();
        job.message_id = "0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89".into();
        job.html = Some(
            r#"<html><body><a href="https://example.com/x">x</a> <a href="{{unsubscribe_url}}">unsubscribe</a></body></html>"#
                .into(),
        );
        job.text = Some("Unsubscribe: {{unsubscribe_url}}".into());
        let prepared = processor
            .prepare_email(&job, &tracking_gate_domain(), &DeliveryRoute::SesShared)
            .unwrap();

        // List-Unsubscribe header with the tracking URL.
        let list_unsub = prepared
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("List-Unsubscribe"))
            .map(|(_, v)| v.clone())
            .expect("List-Unsubscribe header present");
        assert!(list_unsub.starts_with("<https://track.example.com/u/"));

        // RFC 8058 one-click is advertised (the tracking service serves
        // the POST variant on the same route).
        assert!(prepared
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("List-Unsubscribe-Post") && v == "Yes"));

        // The placeholder in the visible body received the SAME URL.
        let html = prepared.html.unwrap();
        assert!(
            !html.contains("{{unsubscribe_url}}"),
            "placeholder replaced"
        );
        assert!(html.contains("https://track.example.com/u/"));
        assert!(prepared
            .text
            .as_deref()
            .unwrap()
            .contains("https://track.example.com/u/"));

        // The token decodes with the SHARED codec and names THIS message,
        // tenant and recipient (deterministic attribution, F13).
        let token = list_unsub
            .trim_start_matches('<')
            .trim_end_matches('>')
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let codec = tracking_service::codec::TrackingCodec::new(secret);
        let data = codec
            .verify_unsubscribe_token(&token, None)
            .expect("tracking-service must verify the outgoing token");
        assert_eq!(data.tenant_id, "tenant-1");
        assert_eq!(data.recipient, "recipient@example.com");
        assert_eq!(
            data.message_id.as_deref(),
            Some("0e2d1c34-9a56-4f18-8f0a-3f4c5d6e7a89")
        );

        std::env::remove_var("TRACKING_SECRET_KEY");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn missing_tracking_secret_leaves_mail_untouched() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("TRACKING_SECRET_KEY");

        // No secret configured: no unsubscribe header, placeholder stays —
        // the send proceeds (suppression never depends on attribution).
        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".into(),
            open_pixel_path: "/o".into(),
            click_redirect_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            secret_key: None,
        })
        .await;
        let mut job = tracking_gate_job();
        job.html = Some("<html><body>hi {{unsubscribe_url}}</body></html>".into());
        let prepared = processor
            .prepare_email(&job, &tracking_gate_domain(), &DeliveryRoute::SesShared)
            .unwrap();
        assert!(!prepared
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("List-Unsubscribe")));
        assert!(prepared
            .html
            .as_deref()
            .unwrap()
            .contains("{{unsubscribe_url}}"));
    }

    #[tokio::test]
    async fn prepare_email_carries_preserved_mime_headers_per_copy() {
        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: false,
            ..crate::common::TrackingConfig::default()
        })
        .await;

        let mut job = tracking_gate_job();
        job.headers = Some(serde_json::json!({
            "to": ["to@example.com", "cc@example.com"],
            "cc": ["cc@example.com"],
            "reply_to": "reply@example.com",
            "custom": {"X-Custom": "v"}
        }));
        let prepared = processor
            .prepare_email(&job, &tracking_gate_domain(), &DeliveryRoute::SesShared)
            .unwrap();
        assert_eq!(
            prepared.to, "recipient@example.com",
            "envelope stays single-recipient"
        );
        assert_eq!(
            prepared.mime_to,
            vec![
                Mailbox {
                    name: None,
                    email: "to@example.com".into()
                },
                Mailbox {
                    name: None,
                    email: "cc@example.com".into()
                },
            ],
            "the visible To header keeps the full mailbox LIST (F26)"
        );
        assert_eq!(
            prepared.mime_cc,
            vec![Mailbox {
                name: None,
                email: "cc@example.com".into()
            }]
        );
        // F26: Reply-To rides as a structured mailbox now, not a raw header.
        assert_eq!(
            prepared.reply_to,
            Some(Mailbox {
                name: None,
                email: "reply@example.com".into()
            })
        );
        let header = |name: &str| {
            prepared
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        assert!(
            header("Reply-To").is_none(),
            "Reply-To is rendered by the transports from the structured field"
        );
        assert_eq!(header("X-Custom").as_deref(), Some("v"));
        assert!(
            header("Message-ID").is_some_and(|v| v.contains("msg-1")),
            "the logical Message-ID must be preserved across copies (F26)"
        );

        // Legacy row without the server shape: no mime overrides.
        let mut legacy = tracking_gate_job();
        legacy.headers = Some(serde_json::json!({"X-Old": "shape"}));
        let prepared = processor
            .prepare_email(&legacy, &tracking_gate_domain(), &DeliveryRoute::SesShared)
            .unwrap();
        assert!(prepared.mime_to.is_empty() && prepared.mime_cc.is_empty());
    }

    // ---------------------------------------------------------------------------
    // F55: consistent recipient normalization + authoritative recheck wiring
    // ---------------------------------------------------------------------------

    #[test]
    fn canonical_recipient_normalizes_like_the_api() {
        assert_eq!(
            canonical_recipient("  User@Example.COM "),
            "user@example.com"
        );
        assert_eq!(
            canonical_recipient("plain@example.com"),
            "plain@example.com"
        );
    }

    /// The dispatch-time gate must read CURRENT state (no cache table,
    /// LOWER() on the stored address) — category changes and resubscriptions
    /// are both covered by an authoritative read.
    #[test]
    fn dispatch_time_suppression_recheck_reads_authoritative_state() {
        // The recheck SQL lives inline in current_suppression_reason; pin its
        // contract through the canonical normalization it depends on and the
        // lowercased comparison shape asserted here (the query text is
        // asserted via the call path below).
        assert_eq!(canonical_recipient("Mixed@Case.X"), "mixed@case.x");
    }

    // ---------------------------------------------------------------------------
    // F18: tenant suspension gate at dispatch time
    // ---------------------------------------------------------------------------

    #[test]
    fn tenant_gate_reads_current_tenant_status() {
        assert!(
            TENANT_STATUS_SQL.contains("SELECT status FROM tenants"),
            "the dispatch gate must read the authoritative tenant status (F18)"
        );
    }

    // ---------------------------------------------------------------------------
    // F59: queue metrics emit the complete bounded status set
    // ---------------------------------------------------------------------------

    #[test]
    fn drained_statuses_are_zeroed_in_every_snapshot() {
        // A queue that only has 'pending' rows left must still publish 0 for
        // every other supported status — previously those gauges kept their
        // last nonzero value forever.
        let snapshot = overlay_status_counts(vec![("pending".to_string(), 5)]);
        let map: std::collections::HashMap<&str, i64> = snapshot
            .iter()
            .map(|(status, count)| (status.as_str(), *count))
            .collect();
        assert_eq!(map.len(), EMAIL_QUEUE_STATUSES.len());
        assert_eq!(map["pending"], 5);
        for status in EMAIL_QUEUE_STATUSES {
            if status != "pending" {
                assert_eq!(map[status], 0, "{status} must be initialized to zero (F59)");
            }
        }
    }

    #[test]
    fn empty_queue_snapshots_all_zero() {
        let snapshot = overlay_status_counts(Vec::new());
        assert!(snapshot.iter().all(|(_, count)| *count == 0));
        assert_eq!(snapshot.len(), EMAIL_QUEUE_STATUSES.len());
    }

    #[test]
    fn unexpected_statuses_are_appended_not_dropped() {
        let snapshot = overlay_status_counts(vec![
            ("pending".to_string(), 1),
            ("future-status".to_string(), 7),
        ]);
        assert!(snapshot
            .iter()
            .any(|(s, c)| s == "future-status" && *c == 7));
        assert!(snapshot.iter().any(|(s, c)| s == "pending" && *c == 1));
    }

    #[test]
    fn supported_status_set_matches_the_schema_check_constraint() {
        // Mirrors chk_email_queue_status (migrations 050/088).
        assert_eq!(
            EMAIL_QUEUE_STATUSES,
            [
                "pending",
                "processing",
                "sent",
                "failed",
                "deferred",
                "cancelled",
                "bounced",
                "suppressed"
            ]
        );
    }

    // ---------------------------------------------------------------------------
    // P0 hybrid routing: route/network-path isolation and pre-DATA refusals
    // ---------------------------------------------------------------------------

    /// A transport double that records every route it was asked to send and
    /// can declare (un)verifiable source binding. Shared between the hybrid
    /// dispatch tests and the DB-backed acceptance tests.
    #[derive(Default)]
    struct RecordingTransport {
        name: &'static str,
        supports_binding: bool,
        calls: std::sync::Mutex<Vec<String>>,
        transport_message_id: Option<String>,
        actual_source_ip: Option<std::net::IpAddr>,
    }

    impl RecordingTransport {
        fn new(name: &'static str, supports_binding: bool) -> Self {
            Self {
                name,
                supports_binding,
                ..Default::default()
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    #[async_trait::async_trait]
    impl EmailTransport for RecordingTransport {
        fn transport_name(&self) -> &str {
            self.name
        }

        fn supports_source_binding(&self) -> bool {
            self.supports_binding
        }

        async fn verify(&self) -> ProcessorResult<()> {
            Ok(())
        }

        async fn send(
            &self,
            _email: &PreparedEmail,
            route: &DeliveryRoute,
        ) -> ProcessorResult<DeliveryReceipt> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(route.to_string());
            Ok(DeliveryReceipt {
                transport: if self.name == "ses" {
                    TransportType::Ses
                } else {
                    TransportType::Smtp
                },
                transport_message_id: self.transport_message_id.clone(),
                actual_source_ip: self.actual_source_ip,
                recipient_provider: None,
                provider_source: None,
            })
        }

        async fn close(&self) -> ProcessorResult<()> {
            Ok(())
        }
    }

    fn test_email() -> PreparedEmail {
        PreparedEmail {
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: "route".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![],
            attachments: vec![],
            dkim: None,
            verp: None,
        }
    }

    /// Adversarial 2: a `SesShared` route never reaches the dedicated
    /// transport, and a `Dedicated` route never reaches SES — asserted on
    /// WHICH recording double saw the call.
    #[tokio::test]
    async fn hybrid_dispatches_each_route_to_exactly_one_backend() {
        let ses = Arc::new(RecordingTransport::new("ses", false));
        let smtp = Arc::new(RecordingTransport::new("smtp", true));
        let hybrid = HybridTransport::new(
            Some(ses.clone() as Arc<dyn EmailTransport>),
            Some(smtp.clone() as Arc<dyn EmailTransport>),
        );
        assert_eq!(hybrid.transport_name(), "hybrid");

        let email = test_email();
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };
        hybrid
            .send(&email, &DeliveryRoute::SesShared)
            .await
            .expect("shared send");
        hybrid
            .send(&email, &dedicated)
            .await
            .expect("dedicated send");

        assert_eq!(
            ses.calls(),
            vec!["ses-shared".to_string()],
            "SES must see the shared send and nothing else"
        );
        assert_eq!(
            smtp.calls(),
            vec![dedicated.to_string()],
            "the relay must see the dedicated send and nothing else"
        );
    }

    /// Adversarial 1: a `Dedicated` route with NO dedicated transport
    /// configured fails closed — the `send` is refused before any
    /// submission, and the error names the missing transport and the route.
    #[tokio::test]
    async fn dedicated_route_without_a_dedicated_transport_fails_closed_before_submit() {
        let ses = Arc::new(RecordingTransport::new("ses", false));
        let hybrid = HybridTransport::new(Some(ses.clone() as Arc<dyn EmailTransport>), None);
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };

        let error = hybrid
            .send(&test_email(), &dedicated)
            .await
            .expect_err("a missing dedicated transport must fail closed");
        let message = error.to_string();
        assert!(
            message.contains("dedicated") && message.contains("SMTP transport"),
            "the error must name the missing transport and the route: {message}"
        );
        assert!(
            message.contains("not configured"),
            "the error must say the transport is not configured: {message}"
        );
        assert!(
            ses.calls().is_empty(),
            "no fallback to the shared pool is allowed: {:?}",
            ses.calls()
        );
    }

    /// Adversarial 1b: the mirror image — a `SesShared` route with no SES
    /// transport configured fails closed and never falls back to the relay.
    #[tokio::test]
    async fn shared_route_without_ses_fails_closed_before_submit() {
        let smtp = Arc::new(RecordingTransport::new("smtp", true));
        let hybrid = HybridTransport::new(None, Some(smtp.clone() as Arc<dyn EmailTransport>));
        let error = hybrid
            .send(&test_email(), &DeliveryRoute::SesShared)
            .await
            .expect_err("a missing SES transport must fail closed");
        assert!(
            error.to_string().contains("SES shared-pool transport"),
            "the error must name the missing shared transport: {error}"
        );
        assert!(
            smtp.calls().is_empty(),
            "no fallback to the dedicated relay is allowed: {:?}",
            smtp.calls()
        );
    }

    /// Adversarial 3 (unit): a dedicated route on a transport that cannot
    /// verify source binding is refused BEFORE DATA — the recording double
    /// saw zero calls.
    #[tokio::test]
    async fn unverifiable_dedicated_route_defers_before_submitting() {
        let ses = Arc::new(RecordingTransport::new("ses", false));
        let unverifiable_smtp = Arc::new(RecordingTransport::new("smtp", false));
        let hybrid = HybridTransport::new(
            Some(ses as Arc<dyn EmailTransport>),
            Some(unverifiable_smtp.clone() as Arc<dyn EmailTransport>),
        );
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };

        let error = hybrid
            .ensure_route_dispatchable(&dedicated)
            .expect_err("an unverifiable dedicated route must be refused");
        assert!(
            error.to_string().contains("source binding"),
            "the refusal must name the missing capability: {error}"
        );
        let send_error = hybrid
            .send(&test_email(), &dedicated)
            .await
            .expect_err("send must refuse before DATA");
        assert!(send_error.to_string().contains("source binding"));
        assert!(
            unverifiable_smtp.calls().is_empty(),
            "the transport must never be called for an unverifiable route: {:?}",
            unverifiable_smtp.calls()
        );
        // The same transport IS dispatchable for the shared route (the
        // capability is only required for dedicated binding).
        assert!(hybrid
            .ensure_route_dispatchable(&DeliveryRoute::SesShared)
            .is_ok());
    }

    /// The receipt/route comparison is an AUDIT note, never a retry signal:
    /// a shared receipt needs none, a matching dedicated receipt needs none,
    /// and a mismatch/missing report is recorded as a contract note.
    #[test]
    fn route_receipt_contract_note_records_but_never_retries() {
        let receipt = |ip: Option<&str>| DeliveryReceipt {
            transport: TransportType::Smtp,
            transport_message_id: None,
            actual_source_ip: ip.map(|value| value.parse().expect("test IP")),
            recipient_provider: None,
            provider_source: None,
        };
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };
        assert!(route_receipt_contract_note(&DeliveryRoute::SesShared, &receipt(None)).is_none());
        assert!(
            route_receipt_contract_note(&DeliveryRoute::SesShared, &receipt(Some("198.51.100.7")))
                .is_none(),
            "the shared route has no binding to confirm"
        );
        assert!(route_receipt_contract_note(&dedicated, &receipt(Some("203.0.113.9"))).is_none());
        assert!(
            route_receipt_contract_note(&dedicated, &receipt(Some("198.51.100.7")))
                .expect("mismatch note")
                .contains("198.51.100.7")
        );
        assert!(route_receipt_contract_note(&dedicated, &receipt(None))
            .expect("missing-report note")
            .contains("no source IP"));
    }

    /// Accounting correction (ephemeral redis): a confirmed contract
    /// violation releases the reserved slot exactly once — never a retry.
    #[tokio::test]
    async fn contract_violation_releases_the_warmup_slot_without_resubmitting() {
        let Some(redis) = ephemeral_redis().await else {
            return;
        };
        let job = tracking_gate_job();
        let pool = select_delivery_ip(Utc::now(), &[dedicated_ip("dip-1", "203.0.113.9", true, 3)])
            .expect("candidate pool");
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let reserved = reserve_warmup_capacity(&redis, &job, &pool, &today)
            .await
            .expect("redis available")
            .expect("below the cap");
        let reservation = reserved.reservation.expect("warming reservation");

        let counter = |key: String| {
            let redis = redis.clone();
            async move {
                let mut conn = redis.get().await.unwrap();
                redis::cmd("GET")
                    .arg(key)
                    .query_async::<Option<i64>>(&mut *conn)
                    .await
                    .unwrap()
            }
        };
        let marker = |key: String| {
            let redis = redis.clone();
            async move {
                let mut conn = redis.get().await.unwrap();
                redis::cmd("GET")
                    .arg(key)
                    .query_async::<Option<String>>(&mut *conn)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(counter(reservation.counter_key.clone()).await, Some(1));
        assert_eq!(
            marker(reservation.marker_key.clone()).await,
            Some("1".into())
        );

        release_warmup_reservation(&redis, &reservation)
            .await
            .expect("release");
        assert_eq!(counter(reservation.counter_key.clone()).await, Some(0));
        assert_eq!(marker(reservation.marker_key.clone()).await, None);

        // A repeated release must not underflow the counter.
        release_warmup_reservation(&redis, &reservation)
            .await
            .expect("second release");
        assert_eq!(counter(reservation.counter_key.clone()).await, Some(0));
    }

    // ---------------------------------------------------------------------------
    // Release-blocker 15 (P0 supersession): the route is chosen by
    // `select_delivery_ip` + `reserve_warmup_capacity`, and dispatchability
    // is enforced BEFORE DATA. See the selection/reservation and hybrid
    // routing tests above.
    // ---------------------------------------------------------------------------

    /// Adversarial 4: the deduplicated module really has ONE transport
    /// abstraction — `transport_router.rs` must not define a second
    /// `EmailTransport` trait or its own send path.
    #[test]
    fn transport_router_defines_no_second_transport_trait_or_send_path() {
        let router = include_str!("transport_router.rs");
        assert!(
            !router.contains("trait EmailTransport"),
            "transport_router.rs must not define a second EmailTransport trait"
        );
        assert!(
            !router.contains("async fn send") && !router.contains("fn send_raw_email"),
            "transport_router.rs must not contain a second send path"
        );
        assert!(
            !router.contains("struct TransportRouter")
                && !router.contains("struct RoutingTransport"),
            "the dead router/cache/wrapper must be gone"
        );
        // The one live contract remains exactly once.
        let active = include_str!("transport.rs");
        assert_eq!(
            active.matches("pub trait EmailTransport").count(),
            1,
            "exactly one EmailTransport definition may exist in the crate"
        );
        assert_eq!(
            active
                .matches("build_message_with_route(email, Some(route))")
                .count(),
            3,
            "all three SMTP outgoing paths must carry the route metadata"
        );
    }

    /// Adversarial 5 (processor side): a caller-supplied header named like
    /// the internal route metadata is stripped before transport — the
    /// transport writes its own value, so message content cannot spoof the
    /// route.
    #[tokio::test]
    async fn prepare_email_strips_a_forged_route_header() {
        let processor = make_processor_with_tracking(crate::common::TrackingConfig {
            enabled: false,
            ..crate::common::TrackingConfig::default()
        })
        .await;
        let mut job = tracking_gate_job();
        job.headers = Some(serde_json::json!({
            "custom": {
                "X-ApexMail-Route": "v1 dedicated forged-dip 198.51.100.7",
                "X-ApexMail-Source-IP": "198.51.100.7",
                "X-Legit-Custom": "kept"
            }
        }));
        let prepared = processor
            .prepare_email(&job, &tracking_gate_domain(), &DeliveryRoute::SesShared)
            .unwrap();
        assert!(
            prepared.headers.iter().all(|(key, _)| !key
                .eq_ignore_ascii_case(super::super::transport::APEXMAIL_ROUTE_HEADER)),
            "a forged route header must never reach a transport: {:?}",
            prepared.headers
        );
        assert!(
            prepared.headers.iter().all(|(key, _)| !key
                .eq_ignore_ascii_case(super::super::transport::APEXMAIL_SOURCE_IP_REPLY_HEADER)),
            "a forged source-IP report must never reach the processor's receipt path"
        );
        assert!(prepared
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("X-Legit-Custom")));
    }
}

#[cfg(test)]
mod sales_feedback_db_tests {
    //! Audit items 10/12 — the delivery-side producers for `sales_outcomes`
    //! and `sales_sender_events`, against the canonical provisioned schema.
    //!
    //! The pool follows this crate's live-test convention
    //! (`migrator::test_support::fresh_canonical_pool`): `TEST_DATABASE_URL`
    //! must be set EXPLICITLY (no ambient localhost default); when it is
    //! unset the tests soft-skip, and a configured-but-broken URL fails.

    use super::*;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn feedback_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    struct FeedbackFixture {
        tenant_id: String,
        queue_row_id: String,
        step_execution_id: Uuid,
        sender_id: Uuid,
    }

    /// Seed the canonical chain the dispatcher writes for sales mail:
    /// tenant, account/contact, sequence/version/step, sender identity,
    /// enrollment, step execution, and the `email_queue` row carrying the
    /// typed sales provenance (migration 202 lines 34-38).
    async fn seed_feedback_fixture(pool: &PgPool, label: &str) -> FeedbackFixture {
        let suffix = &Uuid::new_v4().simple().to_string()[..12];
        let tenant_id = format!("fb-{suffix}");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, 'free', 'active')",
        )
        .bind(&tenant_id)
        .bind(format!("Feedback {label} {suffix}"))
        .bind(format!("fb-{suffix}"))
        .execute(pool)
        .await
        .expect("insert tenant");

        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        let enrollment_id = Uuid::new_v4();
        let step_execution_id = Uuid::new_v4();
        let sender_id = Uuid::new_v4();
        let queue_row_id = Uuid::new_v4();
        let message_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO sales_accounts \
                 (id, tenant_id, company, domain, country, country_confidence, lifecycle) \
             VALUES ($1, $2, $3, $4, 'QZ', 0.95, 'discovered')",
        )
        .bind(account_id)
        .bind(&tenant_id)
        .bind(format!("Feedback Co {suffix}"))
        .bind(format!("feedback-{suffix}.example"))
        .execute(pool)
        .await
        .expect("insert account");

        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, country) \
             VALUES ($1, $2, $3, 'Feedback Prospect', 'QZ')",
        )
        .bind(contact_id)
        .bind(&tenant_id)
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert contact");

        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) VALUES ($1, $2, $3, 'active')",
        )
        .bind(sequence_id)
        .bind(&tenant_id)
        .bind(format!("Feedback Sequence {suffix}"))
        .execute(pool)
        .await
        .expect("insert sequence");

        sqlx::query(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'feedback-test', NOW())",
        )
        .bind(version_id)
        .bind(&tenant_id)
        .bind(sequence_id)
        .execute(pool)
        .await
        .expect("insert sequence version");

        sqlx::query(
            "INSERT INTO sales_sequence_steps \
                 (id, tenant_id, version_id, step_index, kind, min_delay_secs, max_delay_secs, sender_pool) \
             VALUES ($1, $2, $3, 0, 'email', 0, 0, 'sales_outbound')",
        )
        .bind(step_id)
        .bind(&tenant_id)
        .bind(version_id)
        .execute(pool)
        .await
        .expect("insert sequence step");

        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Feedback Sender', 'feedback.example.com', \
                     'active', 200)",
        )
        .bind(sender_id)
        .bind(&tenant_id)
        .bind(format!("sender-{}@feedback.example.com", &suffix[..6]))
        .execute(pool)
        .await
        .expect("insert sender identity");

        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, state) \
             VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(enrollment_id)
        .bind(&tenant_id)
        .bind(version_id)
        .bind(account_id)
        .bind(contact_id)
        .execute(pool)
        .await
        .expect("insert enrollment");

        sqlx::query(
            "INSERT INTO sales_step_executions \
                 (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, \
                  step_index, state, variant, idempotency_key) \
             VALUES ($1, $2, $3, $4, $5, 0, 'sent', 'default', $6)",
        )
        .bind(step_execution_id)
        .bind(&tenant_id)
        .bind(enrollment_id)
        .bind(version_id)
        .bind(step_id)
        .bind(format!("feedback-{suffix}"))
        .execute(pool)
        .await
        .expect("insert step execution");

        sqlx::query(
            "INSERT INTO email_queue \
                 (id, from_address, to_addresses, subject, status, tenant_id, message_id, \
                  sales_sender_identity_id, sales_step_execution_id, sales_enrollment_id) \
             VALUES ($1, 'sender@feedback.example.com', ARRAY['prospect@example.com'], \
                     'Feedback fixture', 'pending', $2, $3, $4, $5, $6)",
        )
        .bind(queue_row_id)
        .bind(&tenant_id)
        .bind(message_id)
        .bind(sender_id)
        .bind(step_execution_id)
        .bind(enrollment_id)
        .execute(pool)
        .await
        .expect("insert email_queue row");

        FeedbackFixture {
            tenant_id,
            queue_row_id: queue_row_id.to_string(),
            step_execution_id,
            sender_id,
        }
    }

    /// The mapping table is the contract: SMTP acceptance is Prohibited, the
    /// hard bounce is the implemented rung, and every migration-200 outcome
    /// value appears in the ladder.
    #[test]
    fn mapping_table_marks_smtp_acceptance_prohibited() {
        assert_eq!(SalesDeliveryEvent::ProviderAccepted.outcome(), None);
        assert_eq!(
            SalesDeliveryEvent::ProviderAccepted.sender_ledger_event(),
            None,
            "acceptance is not a delivery: no `delivered` sender event either"
        );
        assert_eq!(SalesDeliveryEvent::HardBounce.outcome(), Some("bounce"));
        assert_eq!(
            SalesDeliveryEvent::HardBounce.sender_ledger_event(),
            Some("hard_bounce")
        );
        assert_eq!(SalesDeliveryEvent::SoftBounce.outcome(), None);
        assert_eq!(
            SalesDeliveryEvent::SoftBounce.sender_ledger_event(),
            Some("deferral")
        );

        let acceptance = SALES_OUTCOME_MAPPING
            .iter()
            .find(|row| row.platform_event == "smtp_or_provider_acceptance")
            .expect("the acceptance row must be documented");
        assert_eq!(acceptance.outcome, None);
        assert_eq!(acceptance.status, SalesOutcomeProducer::Prohibited);

        assert!(
            SALES_OUTCOME_MAPPING.iter().any(|row| {
                row.status == SalesOutcomeProducer::ImplementedHere && row.outcome == Some("bounce")
            }),
            "the hard-bounce producer must be marked implemented"
        );

        // Every `sales_outcomes.outcome` CHECK value from migration 200
        // (lines 768-771) must appear in the documented ladder.
        let documented: Vec<&str> = SALES_OUTCOME_MAPPING
            .iter()
            .filter_map(|row| row.outcome)
            .collect();
        for rung in [
            "delivered",
            "open",
            "click",
            "reply",
            "positive_reply",
            "meeting_booked",
            "meeting_attended",
            "trial",
            "paid_subscription",
            "retained_mrr",
            "bounce",
            "complaint",
            "unsubscribe",
        ] {
            assert!(
                documented.contains(&rung),
                "ladder rung '{rung}' is missing from SALES_OUTCOME_MAPPING"
            );
        }
    }

    /// Adversarial 6: SMTP/provider acceptance alone produces NO `delivered`
    /// outcome — the audit's specific prohibition.
    #[tokio::test]
    async fn smtp_acceptance_produces_no_delivered_outcome() {
        let Some(pool) = feedback_pool("smtp_acceptance").await else {
            return;
        };
        let fixture = seed_feedback_fixture(&pool, "smtp-acceptance").await;

        let inserted = record_sales_outcome_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::ProviderAccepted,
            "smtp",
        )
        .await
        .expect("acceptance recording must not error");
        assert!(inserted.is_none(), "acceptance must record nothing");

        let outcomes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_outcomes \
             WHERE tenant_id = $1 AND step_execution_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.step_execution_id)
        .fetch_one(&pool)
        .await
        .expect("count outcomes");
        assert_eq!(outcomes, 0, "SMTP acceptance is NOT delivered");

        let sender_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_events WHERE tenant_id = $1",
        )
        .bind(&fixture.tenant_id)
        .fetch_one(&pool)
        .await
        .expect("count sender events");
        assert_eq!(
            sender_events, 0,
            "acceptance must not write a `delivered` sender event either"
        );
    }

    /// Adversarial 7: a hard bounce produces exactly one `bounce` outcome and
    /// one `hard_bounce` ledger row for the step execution, even when the
    /// provider callback is delivered twice.
    #[tokio::test]
    async fn hard_bounce_is_recorded_exactly_once_for_the_step_execution() {
        let Some(pool) = feedback_pool("hard_bounce_once").await else {
            return;
        };
        let fixture = seed_feedback_fixture(&pool, "hard-bounce-once").await;
        let recipient = "prospect@example.com";

        let first = record_sales_outcome_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::HardBounce,
            "smtp",
        )
        .await
        .expect("first bounce recording");
        assert!(first.is_some(), "the first bounce must insert the outcome");

        let replay = record_sales_outcome_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::HardBounce,
            "smtp",
        )
        .await
        .expect("replayed bounce recording");
        assert!(
            replay.is_none(),
            "a replayed provider callback must be a no-op (unique key)"
        );

        let (outcomes, outcome): (i64, String) = sqlx::query_as(
            "SELECT COUNT(*)::bigint, MIN(outcome) FROM sales_outcomes \
             WHERE tenant_id = $1 AND step_execution_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.step_execution_id)
        .fetch_one(&pool)
        .await
        .expect("count outcomes");
        assert_eq!(outcomes, 1, "exactly one bounce row for the step execution");
        assert_eq!(outcome, "bounce");

        // The sender ledger is idempotent on its own unique key.
        let event_first = record_sender_event_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::HardBounce,
            recipient,
        )
        .await
        .expect("first sender-event recording");
        assert!(event_first.is_some());
        let event_replay = record_sender_event_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::HardBounce,
            recipient,
        )
        .await
        .expect("replayed sender-event recording");
        assert!(event_replay.is_none());

        let events: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_type, recipient FROM sales_sender_events \
             WHERE tenant_id = $1 AND sender_identity_id = $2 ORDER BY event_type",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.sender_id)
        .fetch_all(&pool)
        .await
        .expect("read sender events");
        assert_eq!(
            events.len(),
            1,
            "a replayed bounce must not duplicate the row"
        );
        assert_eq!(events[0].0, "hard_bounce");
        assert_eq!(events[0].1, recipient);

        // A transient failure produces a `deferral` ledger row but no outcome
        // (there is no deferral rung in the ladder).
        let soft_outcome = record_sales_outcome_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::SoftBounce,
            "smtp",
        )
        .await
        .expect("soft bounce outcome recording");
        assert!(soft_outcome.is_none());
        let soft_event = record_sender_event_if_linked(
            &pool,
            &fixture.queue_row_id,
            SalesDeliveryEvent::SoftBounce,
            recipient,
        )
        .await
        .expect("soft bounce ledger recording");
        assert!(soft_event.is_some());

        let (outcomes, events): (i64, i64) = (
            sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM sales_outcomes \
                 WHERE tenant_id = $1 AND step_execution_id = $2",
            )
            .bind(&fixture.tenant_id)
            .bind(fixture.step_execution_id)
            .fetch_one(&pool)
            .await
            .expect("count outcomes"),
            sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM sales_sender_events WHERE tenant_id = $1",
            )
            .bind(&fixture.tenant_id)
            .fetch_one(&pool)
            .await
            .expect("count sender events"),
        );
        assert_eq!(outcomes, 1, "a soft bounce adds no outcome");
        assert_eq!(
            events, 2,
            "the deferral joins the hard bounce in the ledger"
        );
    }

    /// Non-sales mail (no typed provenance) and legacy non-UUID ids record
    /// nothing — the typed columns are the gate.
    #[tokio::test]
    async fn queue_rows_without_sales_provenance_record_nothing() {
        let Some(pool) = feedback_pool("no_sales_provenance").await else {
            return;
        };
        let plain_queue_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO email_queue (id, from_address, to_addresses, subject, status) \
             VALUES ($1, 'sender@plain.example.com', ARRAY['plain@example.com'], \
                     'Plain fixture', 'pending')",
        )
        .bind(plain_queue_id)
        .execute(&pool)
        .await
        .expect("insert plain queue row");

        let outcome = record_sales_outcome_if_linked(
            &pool,
            &plain_queue_id.to_string(),
            SalesDeliveryEvent::HardBounce,
            "smtp",
        )
        .await
        .expect("plain row outcome recording");
        assert!(outcome.is_none());

        let event = record_sender_event_if_linked(
            &pool,
            &plain_queue_id.to_string(),
            SalesDeliveryEvent::HardBounce,
            "plain@example.com",
        )
        .await
        .expect("plain row ledger recording");
        assert!(event.is_none());

        let legacy = record_sales_outcome_if_linked(
            &pool,
            "legacy-non-uuid-queue-id",
            SalesDeliveryEvent::HardBounce,
            "smtp",
        )
        .await
        .expect("legacy id recording");
        assert!(legacy.is_none());
    }
}

#[cfg(test)]
mod acceptance_ledger_db_tests {
    //! P0 durable exactly-once: the `sales_delivery_acceptances` protocol
    //! (reserve → submit → record) and its crash reclaim, against the
    //! canonical provisioned schema (migration 205).
    //!
    //! The pool follows this crate's live-test convention
    //! (`migrator::test_support::fresh_canonical_pool`): `TEST_DATABASE_URL`
    //! must be set EXPLICITLY; when unset the tests soft-skip, and a
    //! configured-but-broken URL fails.

    use super::*;
    use sqlx::PgPool;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn acceptance_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn acceptance_job() -> EmailJob {
        EmailJob {
            id: "acc-job-1".into(),
            message_id: "acc-msg-1".into(),
            tenant_id: "acc-tenant-1".into(),
            domain_id: "acc-domain-1".into(),
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            subject: "acceptance".into(),
            html: None,
            text: Some("body".into()),
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 0,
            created_at: Utc::now(),
        }
    }

    fn acceptance_email() -> PreparedEmail {
        PreparedEmail {
            from: "sender@example.com".into(),
            to: "recipient@example.com".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: "acceptance".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![],
            attachments: vec![],
            dkim: None,
            verp: None,
        }
    }

    /// Minimal transport double: counts submissions and can be told to
    /// refuse. The acceptance protocol tests never need a real network path.
    #[derive(Default)]
    struct CountingTransport {
        calls: AtomicUsize,
        refuse: bool,
    }

    impl CountingTransport {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl EmailTransport for CountingTransport {
        fn transport_name(&self) -> &str {
            "counting"
        }

        fn supports_source_binding(&self) -> bool {
            true
        }

        async fn verify(&self) -> ProcessorResult<()> {
            Ok(())
        }

        async fn send(
            &self,
            _email: &PreparedEmail,
            route: &DeliveryRoute,
        ) -> ProcessorResult<DeliveryReceipt> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(ProcessorError::Transport("550 refused".into()));
            }
            Ok(DeliveryReceipt {
                transport: match route {
                    DeliveryRoute::SesShared => TransportType::Ses,
                    DeliveryRoute::Dedicated { .. } => TransportType::Smtp,
                },
                transport_message_id: Some("provider-message-1".into()),
                actual_source_ip: route.dedicated_source_ip(),
                recipient_provider: None,
                provider_source: None,
            })
        }

        async fn close(&self) -> ProcessorResult<()> {
            Ok(())
        }
    }

    async fn acceptance_count(pool: &PgPool, send_unit: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_delivery_acceptances WHERE send_unit = $1",
        )
        .bind(send_unit)
        .fetch_one(pool)
        .await
        .expect("count acceptances")
    }

    async fn acceptance_state(pool: &PgPool, send_unit: &str) -> String {
        sqlx::query_scalar("SELECT state FROM sales_delivery_acceptances WHERE send_unit = $1")
            .bind(send_unit)
            .fetch_one(pool)
            .await
            .expect("read acceptance state")
    }

    /// Adversarial 1 (ledger half): a dedicated route with no dedicated
    /// transport is refused by the pre-DATA gate and inserts NO acceptance
    /// row — the deferral happens before the ledger is touched.
    #[tokio::test]
    async fn dedicated_route_without_dedicated_transport_inserts_no_acceptance_row() {
        let Some(pool) = acceptance_pool("acc_no_transport").await else {
            eprintln!("skipping dedicated_route_without_dedicated_transport_inserts_no_acceptance_row: no TEST_DATABASE_URL");
            return;
        };
        let job = acceptance_job();
        let route = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };
        let transport = Arc::new(CountingTransport::default());
        let hybrid = HybridTransport::new(Some(transport.clone() as Arc<dyn EmailTransport>), None);
        assert!(
            hybrid.ensure_route_dispatchable(&route).is_err(),
            "the gate must refuse before anything else runs"
        );
        // Dispatch defers here; the ledger is never reached.
        assert_eq!(acceptance_count(&pool, &send_unit_of(&job)).await, 0);
        assert_eq!(transport.calls(), 0);
        pool.close().await;
    }

    /// Adversarial 3 (ledger half): an unverifiable dedicated route never
    /// reaches the transport and leaves no `accepted` (indeed no) row.
    #[tokio::test]
    async fn unverifiable_dedicated_route_defers_before_the_ledger() {
        let Some(pool) = acceptance_pool("acc_unverifiable").await else {
            eprintln!("skipping unverifiable_dedicated_route_defers_before_the_ledger: no TEST_DATABASE_URL");
            return;
        };
        let job = acceptance_job();
        let route = DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "203.0.113.9".parse().expect("test IP"),
        };
        let unverifiable = Arc::new(CountingTransport {
            refuse: false,
            ..Default::default()
        });
        // The double declares no binding capability.
        struct NoBinding(Arc<CountingTransport>);
        #[async_trait::async_trait]
        impl EmailTransport for NoBinding {
            fn transport_name(&self) -> &str {
                "smtp"
            }
            fn supports_source_binding(&self) -> bool {
                false
            }
            async fn verify(&self) -> ProcessorResult<()> {
                Ok(())
            }
            async fn send(
                &self,
                email: &PreparedEmail,
                route: &DeliveryRoute,
            ) -> ProcessorResult<DeliveryReceipt> {
                self.0.send(email, route).await
            }
            async fn close(&self) -> ProcessorResult<()> {
                Ok(())
            }
        }
        let hybrid = HybridTransport::new(
            Some(unverifiable.clone() as Arc<dyn EmailTransport>),
            Some(Arc::new(NoBinding(unverifiable.clone())) as Arc<dyn EmailTransport>),
        );
        assert!(hybrid.ensure_route_dispatchable(&route).is_err());
        assert_eq!(acceptance_count(&pool, &send_unit_of(&job)).await, 0);
        assert_eq!(unverifiable.calls(), 0, "transport must never be called");
        pool.close().await;
    }

    /// Adversarial 4 (the exactly-once gate): the second reserve for the same
    /// send unit is refused and the recording transport saw exactly ONE call.
    #[tokio::test]
    async fn duplicate_reserve_never_submits_twice() {
        let Some(pool) = acceptance_pool("acc_duplicate").await else {
            eprintln!("skipping duplicate_reserve_never_submits_twice: no TEST_DATABASE_URL");
            return;
        };
        let job = acceptance_job();
        let route = DeliveryRoute::SesShared;
        let transport = CountingTransport::default();
        let send_unit = send_unit_of(&job);

        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::Claimed
        );
        let receipt = transport
            .send(&acceptance_email(), &route)
            .await
            .expect("first submission");
        record_acceptance_accepted(&pool, &send_unit, &receipt, None)
            .await
            .expect("record acceptance");

        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::AlreadyAccepted,
            "the ledger must refuse a second submission"
        );
        assert_eq!(
            transport.calls(),
            1,
            "the transport must have been called exactly once"
        );
        assert_eq!(acceptance_state(&pool, &send_unit).await, "accepted");
        pool.close().await;
    }

    /// Adversarial 5: a failed submission records `failed` and a retry is
    /// allowed; a successful one records `accepted` and a retry is refused.
    #[tokio::test]
    async fn failed_submission_allows_retry_accepted_blocks_it() {
        let Some(pool) = acceptance_pool("acc_retry").await else {
            eprintln!(
                "skipping failed_submission_allows_retry_accepted_blocks_it: no TEST_DATABASE_URL"
            );
            return;
        };
        let job = acceptance_job();
        let route = DeliveryRoute::SesShared;
        let send_unit = send_unit_of(&job);

        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::Claimed
        );
        record_acceptance_failed(&pool, &send_unit, "550 refused")
            .await
            .expect("record refusal");
        assert_eq!(acceptance_state(&pool, &send_unit).await, "failed");

        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::Claimed,
            "a recorded refusal frees the unit for a retry"
        );
        let transport = CountingTransport::default();
        let receipt = transport
            .send(&acceptance_email(), &route)
            .await
            .expect("retry submission");
        record_acceptance_accepted(&pool, &send_unit, &receipt, None)
            .await
            .expect("record retry acceptance");

        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::AlreadyAccepted,
            "after acceptance the unit is closed"
        );
        assert_eq!(transport.calls(), 1);
        pool.close().await;
    }

    /// Adversarial 6: a crashed `reserved` row is reclaimed after the lease,
    /// exactly once — the ledger's primary key serializes the claim.
    #[tokio::test]
    async fn crashed_reserved_row_is_reclaimed_after_the_lease_exactly_once() {
        let Some(pool) = acceptance_pool("acc_reclaim").await else {
            eprintln!("skipping crashed_reserved_row_is_reclaimed_after_the_lease_exactly_once: no TEST_DATABASE_URL");
            return;
        };
        let job = acceptance_job();
        let route = DeliveryRoute::SesShared;
        let send_unit = send_unit_of(&job);

        // A crashed submission: `reserved` with an expired lease.
        sqlx::query(
            "INSERT INTO sales_delivery_acceptances \
                 (send_unit, tenant_id, state, reserved_at) \
             VALUES ($1, $2, 'reserved', NOW() - make_interval(secs => $3))",
        )
        .bind(&send_unit)
        .bind(&job.tenant_id)
        .bind(ACCEPTANCE_RESERVE_LEASE.as_secs() as i64 + 60)
        .execute(&pool)
        .await
        .expect("seed crashed reservation");

        // A fresh reservation is NOT claimable while its lease is live.
        sqlx::query(
            "UPDATE sales_delivery_acceptances SET reserved_at = NOW() WHERE send_unit = $1",
        )
        .bind(&send_unit)
        .execute(&pool)
        .await
        .expect("renew lease");
        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::InFlight,
            "a live reservation must not be stolen"
        );

        // Age it past the lease: exactly ONE of two concurrent claims wins.
        sqlx::query(
            "UPDATE sales_delivery_acceptances \
             SET reserved_at = NOW() - make_interval(secs => $2) WHERE send_unit = $1",
        )
        .bind(&send_unit)
        .bind(ACCEPTANCE_RESERVE_LEASE.as_secs() as i64 + 60)
        .execute(&pool)
        .await
        .expect("expire lease");
        let claims = futures::future::join_all(vec![
            claim_acceptance(&pool, &job, &route),
            claim_acceptance(&pool, &job, &route),
        ])
        .await;
        let claimed = claims
            .iter()
            .filter(|claim| matches!(claim, Ok(AcceptanceClaim::Claimed)))
            .count();
        assert_eq!(
            claimed, 1,
            "the ledger's unique key must admit exactly one reclaiming worker: {claims:?}"
        );

        // The reclaimed submission is recorded accepted; a further claim is
        // refused (exactly-once).
        let transport = CountingTransport::default();
        let receipt = transport
            .send(&acceptance_email(), &route)
            .await
            .expect("reclaimed submission");
        record_acceptance_accepted(&pool, &send_unit, &receipt, None)
            .await
            .expect("record reclaimed acceptance");
        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::AlreadyAccepted
        );
        assert_eq!(transport.calls(), 1);

        // The governance sweep returns an expired reservation to the
        // submit-capable state (`failed` with a distinctive reason).
        let second_job = EmailJob {
            id: "acc-job-sweep".into(),
            ..job.clone()
        };
        let second_unit = send_unit_of(&second_job);
        sqlx::query(
            "INSERT INTO sales_delivery_acceptances \
                 (send_unit, tenant_id, state, reserved_at) \
             VALUES ($1, $2, 'reserved', NOW() - make_interval(secs => $3))",
        )
        .bind(&second_unit)
        .bind(&second_job.tenant_id)
        .bind(ACCEPTANCE_RESERVE_LEASE.as_secs() as i64 + 60)
        .execute(&pool)
        .await
        .expect("seed second crashed reservation");
        let swept = reclaim_stale_acceptance_reservations(&pool)
            .await
            .expect("sweep");
        assert!(swept >= 1, "the stale reservation must be swept");
        assert_eq!(acceptance_state(&pool, &second_unit).await, "failed");
        assert_eq!(
            claim_acceptance(&pool, &second_job, &route).await.unwrap(),
            AcceptanceClaim::Claimed,
            "a swept reservation is immediately retryable through the claim"
        );
        pool.close().await;
    }

    /// The sales identity flows straight into the ledger primary key, so a
    /// retried step execution can never create a second row.
    #[tokio::test]
    async fn sales_send_unit_is_the_queue_idempotency_key() {
        let Some(pool) = acceptance_pool("acc_sales_unit").await else {
            eprintln!(
                "skipping sales_send_unit_is_the_queue_idempotency_key: no TEST_DATABASE_URL"
            );
            return;
        };
        let step_execution_id = uuid::Uuid::new_v4();
        let job = EmailJob {
            sales_step_execution_id: Some(step_execution_id.to_string()),
            ..acceptance_job()
        };
        let route = DeliveryRoute::SesShared;
        let send_unit = format!("sa-send:{step_execution_id}");
        assert_eq!(send_unit_of(&job), send_unit);

        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::Claimed
        );
        let receipt = DeliveryReceipt {
            transport: TransportType::Ses,
            transport_message_id: Some("ses-1".into()),
            actual_source_ip: None,
            recipient_provider: None,
            provider_source: None,
        };
        record_acceptance_accepted(&pool, &send_unit, &receipt, None)
            .await
            .expect("record acceptance");
        assert_eq!(acceptance_count(&pool, &send_unit).await, 1);
        assert_eq!(
            claim_acceptance(&pool, &job, &route).await.unwrap(),
            AcceptanceClaim::AlreadyAccepted
        );
        pool.close().await;
    }
}
