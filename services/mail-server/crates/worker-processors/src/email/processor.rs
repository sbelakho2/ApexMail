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
use moka::sync::Cache;
use rand::Rng;
use sqlx::PgPool;
use std::sync::Mutex;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::tracking::{add_tracking_pixel, rewrite_links};
use super::transport::{create_transport_from_config, EmailTransport};
use super::types::{
    Attachment, CachedSuppression, DkimConfig, Domain, EmailJob, PreparedEmail, SendOutcome,
    SendResult, WarmupLimits,
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
            COALESCE(metadata, '{}'::jsonb),
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
            COALESCE(metadata, '{}'::jsonb),
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
            COALESCE(metadata, '{}'::jsonb),
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

/// D: mirror of the SES notification handler's message transition
/// (api-server ses_notifications.rs updates messages.status on delivery
/// events). The SMTP path has no out-of-band notifications, so an accepted
/// send IS the terminal message state: 'queued' → 'sent'. Only rows still in
/// 'queued' transition — never crouch 'bounced'/'delivered' set elsewhere.
const MESSAGES_SENT_UPDATE_SQL: &str = r#"
    UPDATE messages SET status = 'sent', updated_at = NOW()
    WHERE id = $1::uuid AND tenant_id = $2 AND status = 'queued'
"#;

/// Audit-1: the ready-domain lookup for a queued job.
///
/// Warmup state comes from the REAL warmup tables: per-IP warmup lives on
/// `dedicated_ips` (created by migration 003 with `warmup_started_at`, given
/// the per-IP warmup model by migrations 071/093 — the same table
/// `transport_router.rs` routes on), so the query returns the
/// `warmup_started_at` timestamps of the tenant's dedicated IPs still in
/// status 'warming' and the day/enabled derivation happens in Rust
/// ([`derive_domain_warmup`]). A domain whose tenant has no warming
/// dedicated IP (shared SES pool) derives warmup DISABLED — correct: the
/// shared pool rides platform reputation, not the tenant's.
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
        NULL::text AS return_path,
        w.warmup_starts AS warmup_starts
    FROM domains d
    LEFT JOIN LATERAL (
        SELECT ARRAY(
            SELECT di.warmup_started_at
            FROM dedicated_ips di
            WHERE di.tenant_id = d.tenant_id
              AND di.status = 'warming'
              AND di.warmup_started_at IS NOT NULL
        ) AS warmup_starts
    ) w ON true
    WHERE d.id = $1::uuid AND d.tenant_id = $2
      AND d.status = 'verified'
      AND d.dkim_enabled = true
      AND d.dkim_selector IS NOT NULL
      AND d.dkim_public_key IS NOT NULL
      AND d.dkim_private_key IS NOT NULL
      AND d.dkim_private_key LIKE 'dkim:v1:%'
      AND ($3::boolean = false OR d.ses_verified = true)
"#;

/// Audit-1: [`GET_DOMAIN_SQL`] row — the [`Domain`] columns plus the warmup
/// source data (`warmup_started_at` of every warming dedicated IP).
#[derive(Debug, sqlx::FromRow)]
struct DomainWithWarmupRow {
    id: String,
    tenant_id: String,
    domain: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
    dkim_private_key: Option<String>,
    return_path: Option<String>,
    warmup_starts: Option<Vec<DateTime<Utc>>>,
}

/// Audit-1: derive the domain's effective warmup state from the
/// `warmup_started_at` timestamps of the tenant's dedicated IPs that are
/// still warming.
///
/// * no warming IP → `(false, 0)`: the domain sends on the shared pool and
///   `check_warmup_limit` must not engage;
/// * otherwise enabled, with the binding day = the SMALLEST whole-days
///   elapsed across the warming IPs — the least-warmed IP is the constraint
///   on the tenant's reputation;
/// * day never goes negative (a just-started or clock-skewed future
///   timestamp clamps to day 0).
fn derive_domain_warmup(now: DateTime<Utc>, warmup_starts: &[DateTime<Utc>]) -> (bool, i32) {
    let mut binding_day: Option<i32> = None;
    for started_at in warmup_starts {
        let elapsed_days = (now - started_at).num_days().clamp(0, i32::MAX as i64) as i32;
        binding_day = Some(match binding_day {
            Some(day) => day.min(elapsed_days),
            None => elapsed_days,
        });
    }
    match binding_day {
        Some(day) => (true, day),
        None => (false, 0),
    }
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
                    COALESCE(metadata, '{}'::jsonb),
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
                    WHEN metadata->'pending_recipients' IS NOT NULL
                    THEN ARRAY(
                        SELECT jsonb_array_elements_text(metadata->'pending_recipients')
                    )
                    ELSE to_addresses
                END as "toAddresses",
                subject, html, text, headers, attachments,
                campaign_id::text as "campaignId", tags, metadata, scheduled_at as "scheduledAt",
                attempt, created_at as "createdAt"
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
                    COALESCE(metadata, '{}'::jsonb),
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
                    COALESCE(metadata, '{}'::jsonb),
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
                metadata = jsonb_set(COALESCE(metadata, '{}'), '{requeue_reason}', $2::jsonb)
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
                COALESCE(metadata, '{}'::jsonb),
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

/// G.3c: send-idempotency marker key — one marker per (row, attempt,
/// recipient), the exact unit of `transport.send`. Held with the row's
/// visibility lease so a crashed worker's reclaim hits the marker.
fn send_marker_key(job: &EmailJob) -> String {
    format!("email:send:{}:{}:{}", job.id, job.attempt, job.to)
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

/// Audit-2: the two admission buckets a send must reserve from — the
/// tenant-wide ceiling and the sending domain's own bucket.
fn send_admission_keys(job: &EmailJob) -> Vec<String> {
    vec![
        format!("rl:send:tenant:{}", job.tenant_id),
        format!("rl:send:domain:{}", job.domain_id),
    ]
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

/// G.3c: try to claim the send slot (Redis SET NX EX). `Ok(true)` — we own
/// this send; `Ok(false)` — a previous claim may already have sent (crashed
/// worker, expired lease); `Err` — Redis unavailable (best-effort mode: the
/// send proceeds, logged).
async fn try_claim_send_slot(
    redis: &RedisPool,
    job: &EmailJob,
    ttl_secs: u64,
) -> Result<bool, String> {
    let mut conn = redis.get().await.map_err(|e| e.to_string())?;
    let claimed: Option<String> = redis::cmd("SET")
        .arg(send_marker_key(job))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs.max(1))
        .query_async(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(claimed.is_some())
}

/// G.3c: release the send marker once the attempt is fully handled.
async fn release_send_slot(redis: &RedisPool, job: &EmailJob) {
    match redis.get().await {
        Ok(mut conn) => {
            let _: () = redis::cmd("DEL")
                .arg(send_marker_key(job))
                .query_async(&mut *conn)
                .await
                .unwrap_or(());
        }
        Err(e) => warn!(error = %e, "failed to release send idempotency marker"),
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
    tags: Option<Vec<String>>,
    metadata: Option<serde_json::Value>,
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
            tags: row.tags.clone(),
            metadata: row.metadata.clone(),
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

/// Email processor for sending emails from the queue.
pub struct EmailProcessor {
    db: PgPool,
    redis: RedisPool,
    config: EmailConfig,
    transport: Box<dyn EmailTransport>,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Arc<Notify>,

    // Caches
    suppression_cache: Cache<String, CachedSuppression>,
    #[expect(
        dead_code,
        reason = "warmup day cache is retained for scheduled warmup routing integration"
    )]
    warmup_day_cache: Cache<String, i32>,

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
            shutdown_notify: Arc::new(Notify::new()),
            suppression_cache: Cache::builder()
                .max_capacity(SUPPRESSION_CACHE_MAX_SIZE)
                .time_to_live(SUPPRESSION_CACHE_TTL)
                .build(),
            warmup_day_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(3600))
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
                        let suppression =
                            suppressions.get(&format!("{}:{}", job.tenant_id, job.to));
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

    /// Batch suppression check for efficiency.
    async fn batch_suppression_check(&self, jobs: &[EmailJob]) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // Group by tenant
        let mut by_tenant: HashMap<String, Vec<&str>> = HashMap::new();
        for job in jobs {
            by_tenant
                .entry(job.tenant_id.clone())
                .or_default()
                .push(&job.to);
        }

        for (tenant_id, emails) in by_tenant {
            // Check cache first
            let mut uncached: Vec<&str> = Vec::new();
            for email in &emails {
                let cache_key = format!("{}:{}", tenant_id, email);
                if let Some(cached) = self.suppression_cache.get(&cache_key) {
                    if cached.suppressed {
                        result.insert(cache_key, cached.reason.clone().unwrap_or_default());
                    }
                } else {
                    uncached.push(*email);
                }
            }

            // Query database for uncached
            if !uncached.is_empty() {
                // to avoid sending to potentially suppressed recipients.
                let db_result = sqlx::query_as::<_, (String, String)>(
                    r#"
                    SELECT email, reason
                    FROM suppressions
                    WHERE tenant_id = $1 AND email = ANY($2)
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

                // Cache and collect positive results
                for (email, reason) in suppressions {
                    let cache_key = format!("{}:{}", tenant_id, email);
                    self.suppression_cache.insert(
                        cache_key.clone(),
                        CachedSuppression {
                            suppressed: true,
                            reason: Some(reason.clone()),
                            expires_at: Instant::now() + SUPPRESSION_CACHE_TTL,
                        },
                    );
                    result.insert(cache_key, reason);
                }

                // Cache negative results
                for email in &uncached {
                    if !suppressed_emails.contains(*email) {
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
        // Check circuit breaker
        if !self.smtp_circuit_breaker.is_allowed() {
            return Err(ProcessorError::CircuitOpen(
                "SMTP circuit breaker open".into(),
            ));
        }

        // Load and validate current domain state before any per-domain rate
        // accounting or delivery. A queued job can outlive a domain's
        // verification or deletion, so API-time authorization alone is not
        // enough.
        let domain = self.get_domain(job).await?;

        // Check warmup limits
        if self.config.warmup.enabled && !self.check_warmup_limit(job, &domain).await? {
            self.requeue_job(job, "warmup_limit").await?;
            return Ok(());
        }

        // Prepare email
        let email = self.prepare_email(job, &domain)?;

        // Audit-2: send-time admission control — reserve one send from the
        // tenant and domain token buckets (rate from
        // `EmailConfig::send_rate_per_second`, previously dead config) BEFORE
        // the transport. On exhaustion the row is deferred through the same
        // requeue path as the warmup gate; the attempt is untouched, so the
        // next claim re-evaluates admission.
        if !self.check_send_admission(job).await? {
            debug!(
                job_id = %job.id,
                tenant_id = %job.tenant_id,
                domain_id = %job.domain_id,
                "send admission exhausted — deferring row"
            );
            self.requeue_job(job, "send_rate_limited").await?;
            return Ok(());
        }

        // G.3c: send idempotency — claim the (row, attempt, recipient) send
        // slot before touching the transport. A reclaim whose previous
        // attempt may have sent (lease expired mid-send) finds the marker
        // still held and does NOT re-send; the recipient is recorded as
        // possibly-sent instead. The X-ApexMail-Message-ID header added by
        // prepare_email lets downstream systems dedupe the rare true
        // duplicate. Best-effort: without Redis the send proceeds (logged).
        let marker_ttl_secs = self.config.base.visibility_timeout.as_secs().max(1);
        match try_claim_send_slot(&self.redis, job, marker_ttl_secs).await {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    job_id = %job.id,
                    recipient = %job.to,
                    attempt = job.attempt,
                    "send marker still held — previous attempt may have sent; skipping re-send"
                );
                self.handle_possibly_sent(job).await?;
                return Ok(());
            }
            Err(e) => {
                warn!(
                    job_id = %job.id,
                    error = %e,
                    "send idempotency marker unavailable — proceeding (best-effort)"
                );
            }
        }

        // Send email
        let send_result = self.transport.send(&email).await;

        // Per-attempt delivery log (email_delivery_log) — the table
        // delivery_analytics' latency percentiles and billing's usage ingest
        // read; previously no runtime writer existed, so those surfaces were
        // structurally zero. Best-effort: a logging failure must not fail
        // the send path.
        match &send_result {
            Ok(result) => {
                self.record_delivery_attempt(job, true, Some(&result.response), None)
                    .await;
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
                // below max_retries and DLQs above.
                match classify_send_failure(&e) {
                    SendFailureClass::Soft => self.handle_soft_bounce(job, &e).await?,
                    SendFailureClass::Hard => self.handle_hard_bounce(job, &e).await?,
                    SendFailureClass::Unknown => self.handle_error(job, &e).await?,
                }

                Err(e)
            }
        };

        // G.3c: release the marker once the attempt is fully handled — on
        // success the pending set already excludes this recipient; on
        // failure the next attempt mints a fresh marker (attempt increments).
        release_send_slot(&self.redis, job).await;

        outcome
    }

    /// Audit-2: send-time admission gate — reserve one send from the tenant
    /// and domain token buckets (refilled from
    /// [`EmailConfig::send_rate_per_second`]) before any transport.send.
    ///
    /// * `Ok(false)` — exhausted: the caller defers the row via the existing
    ///   requeue path instead of sending.
    /// * `Err`/Redis unavailable — fails OPEN with a warning (best-effort,
    ///   matching the G.3c send marker's posture; the transports still
    ///   enforce their own server-side throttling).
    /// * rate 0 — the gate is disabled entirely.
    async fn check_send_admission(&self, job: &EmailJob) -> ProcessorResult<bool> {
        let rate = self.config.send_rate_per_second();
        if rate == 0 {
            return Ok(true);
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        match reserve_send_admission(&self.redis, &send_admission_keys(job), rate, now_ms).await {
            Ok(admitted) => Ok(admitted),
            Err(e) => {
                warn!(
                    job_id = %job.id,
                    tenant_id = %job.tenant_id,
                    error = %e,
                    "send admission bucket unavailable — proceeding (best-effort)"
                );
                Ok(true)
            }
        }
    }

    /// Check warmup limits for a domain.
    ///
    /// # Security (O-16.8)
    ///
    /// **Root cause**: Previously used an in-memory `RwLock<HashMap<String, i64>>`
    /// which is local to each process. Multiple workers would each have their own
    /// counter, allowing up to N × daily_limit sends per domain (where N is the
    /// number of workers). This is a bypass of warmup rate limiting.
    ///
    /// **Fix**: Replaced the per-process `HashMap` with a Redis `INCR` + `EXPIRE`
    /// key (`warmup:count:<date>:<domain_id>`). The key has a 24-hour TTL and uses
    /// atomic `INCR` for cross-worker correctness. The first worker to increment
    /// (return value == 1) also sets the TTL via `EXPIRE` (race-safe; extra EXPIRE
    /// calls are harmless). All workers share a single counter per domain per day.
    async fn check_warmup_limit(&self, job: &EmailJob, domain: &Domain) -> ProcessorResult<bool> {
        if !domain.warmup_enabled {
            return Ok(true);
        }

        let limits = WarmupLimits::for_day(domain.warmup_day);

        // Use Redis INCR for atomic cross-worker counters with 24h TTL.
        // Key format: warmup:count:<YYYY-MM-DD>:<domain_id>
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let redis_key = format!("warmup:count:{}:{}", today, job.domain_id);

        let mut conn = self.redis.get().await.map_err(|e| {
            warn!(domain_id = %job.domain_id, error = %e, "Failed to get Redis connection for warmup check");
            ProcessorError::Job(format!("Redis unavailable for warmup check: {}", e))
        })?;

        // Atomically increment the counter — shared across all workers
        let current: i64 = redis::cmd("INCR")
            .arg(&redis_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                warn!(domain_id = %job.domain_id, error = %e, "Redis INCR failed for warmup check");
                ProcessorError::Job(format!("Redis INCR failed: {}", e))
            })?;

        // Set expiry on first increment (return value == 1 means this is a new key).
        // Race-safe: multiple workers may call EXPIRE concurrently, which is idempotent.
        if current == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&redis_key)
                .arg(86400) // 24 hours
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
        }

        if current > limits.daily_limit {
            // We've exceeded the limit. Decrement to keep the counter accurate.
            let _: () = redis::cmd("DECR")
                .arg(&redis_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the ready sending-domain configuration for a queued job.
    ///
    /// Legacy jobs without a registered domain are permanently rejected: an
    /// unsigned fallback would turn a revoked or spoofed sender into delivery.
    ///
    /// Audit-1: warmup state is derived from the REAL per-tenant warmup data
    /// (see [`GET_DOMAIN_SQL`]) instead of hardcoded `false/0` — the previous
    /// constants made `check_warmup_limit` structurally dead.
    async fn get_domain(&self, job: &EmailJob) -> ProcessorResult<Domain> {
        if job.domain_id.is_empty() {
            return Err(ProcessorError::Job(
                "queued message has no authorized sending domain".into(),
            ));
        }

        let requires_ses = self.config.transport_type == TransportType::Ses;
        let row = sqlx::query_as::<_, DomainWithWarmupRow>(GET_DOMAIN_SQL)
            .bind(&job.domain_id)
            .bind(&job.tenant_id)
            .bind(requires_ses)
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(|| {
                ProcessorError::Job(format!(
                    "sending domain is absent, unverified, incomplete, or not ready for {} delivery",
                    if requires_ses { "SES" } else { "SMTP" }
                ))
            })?;

        let (warmup_enabled, warmup_day) =
            derive_domain_warmup(Utc::now(), row.warmup_starts.as_deref().unwrap_or(&[]));
        let domain = Domain {
            id: row.id,
            tenant_id: row.tenant_id,
            domain: row.domain,
            dkim_selector: row.dkim_selector,
            dkim_public_key: row.dkim_public_key,
            dkim_private_key: row.dkim_private_key,
            warmup_enabled,
            warmup_day,
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

    /// Prepare email for sending.
    fn prepare_email(&self, job: &EmailJob, domain: &Domain) -> ProcessorResult<PreparedEmail> {
        let mut html = job.html.clone();

        // Add tracking if enabled
        if self.config.tracking.enabled {
            if let Some(ref h) = html {
                let tracked = add_tracking_pixel(h, job, &self.config.tracking);
                let tracked = rewrite_links(&tracked, job, &self.config.tracking);
                html = Some(tracked);
            }
        }

        // Build headers
        let mut headers = vec![
            ("X-ApexMail-Message-ID".to_string(), job.message_id.clone()),
            ("X-ApexMail-Tenant-ID".to_string(), job.tenant_id.clone()),
        ];

        if let Some(ref campaign_id) = job.campaign_id {
            headers.push(("X-ApexMail-Campaign-ID".to_string(), campaign_id.clone()));
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
            "x-apexmail-message-id",
            "x-apexmail-tenant-id",
            "x-apexmail-campaign-id",
            "x-originating-ip",
            "x-mailer",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
        ];

        // Add custom headers from job (filtering protected headers)
        if let Some(ref job_headers) = job.headers {
            if let Some(obj) = job_headers.as_object() {
                for (key, value) in obj {
                    let key_lower = key.to_lowercase();
                    if PROTECTED_HEADERS.contains(&key_lower.as_str()) {
                        tracing::warn!(header = %key, "Blocked attempt to set protected header via custom headers");
                        continue;
                    }
                    if let Some(v) = value.as_str() {
                        headers.push((key.clone(), v.to_string()));
                    }
                }
            }
        }

        // SMTP delivery signs with the key whose public half was displayed in
        // the dashboard. SES delivery is signed by SES BYODKIM using that same
        // key, so it intentionally does not attach a second local signature.
        let dkim = if self.config.transport_type == TransportType::Smtp {
            if !self.config.dkim.enabled {
                return Err(ProcessorError::Config(
                    "DKIM is required for SMTP delivery of verified domains".into(),
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
            subject: job.subject.clone(),
            html,
            text: job.text.clone(),
            headers,
            attachments,
            dkim,
        })
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
    async fn handle_success(&self, job: &EmailJob, result: &SendResult) -> ProcessorResult<()> {
        let updated = sqlx::query(HANDLE_SUCCESS_UPDATE_SQL)
            .bind(&result.smtp_message_id)
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

        // Record sent event
        sqlx::query(
            r#"
            INSERT INTO events (id, tenant_id, message_id, domain_id, campaign_id, event_type, recipient, timestamp)
            VALUES ($1, $2, $3, $4, $5, 'sent', $6, NOW())
            "#,
        )
        .bind(format!("evt_{}", uuid::Uuid::new_v4()))
        .bind(&job.tenant_id)
        .bind(&job.message_id)
        .bind(&job.domain_id)
        .bind(&job.campaign_id)
        .bind(&job.to)
        .execute(&self.db)
        .await?;

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
        .bind(transport_provider_label(&self.config.transport_type))
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

        // D: transition the audit `messages` row 'queued' → 'sent' (the SMTP
        // counterpart of the SES delivery-notification handler). Best-effort
        // parse: a legacy job without a UUID message id skips the transition
        // rather than failing the (already successful) send handling.
        if let Ok(message_uuid) = uuid::Uuid::parse_str(&job.message_id) {
            sqlx::query(MESSAGES_SENT_UPDATE_SQL)
                .bind(message_uuid)
                .bind(&job.tenant_id)
                .execute(&self.db)
                .await?;
        }

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
        }

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
        }

        Ok(())
    }

    /// Handle soft bounce (retry later).
    async fn handle_soft_bounce(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
    ) -> ProcessorResult<()> {
        if job.attempt >= self.config.base.max_retries as i32 {
            return self.handle_hard_bounce(job, error).await;
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
        }

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

        // Add to suppressions — ONLY the bounced address. suppressions.id is
        // VARCHAR(26), so use a short random suffix ("sup_" + 18 hex chars
        // = 22 chars).
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

        // Record bounce event (for the bounced recipient only)
        sqlx::query(
            r#"
            INSERT INTO events (id, tenant_id, message_id, domain_id, campaign_id, event_type, recipient, timestamp)
            VALUES ($1, $2, $3, $4, $5, 'bounced', $6, NOW())
            "#,
        )
        .bind(format!("evt_{}", uuid::Uuid::new_v4()))
        .bind(&job.tenant_id)
        .bind(&job.message_id)
        .bind(&job.domain_id)
        .bind(&job.campaign_id)
        .bind(&job.to)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Handle generic error.
    async fn handle_error(&self, job: &EmailJob, error: &ProcessorError) -> ProcessorResult<()> {
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
            self.handle_soft_bounce(job, error).await?;
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

/// Envelope-sender domain used for per-domain reputation counters.
fn envelope_domain(from: &str) -> Option<&str> {
    from.rsplit_once('@').map(|(_, d)| d)
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
            tags: None,
            metadata: None,
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
            return_path: None,
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
        let prepared = processor.prepare_email(&job, &domain).unwrap();
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
            secret_key: None,
        })
        .await;

        let job = tracking_gate_job();
        let domain = tracking_gate_domain();
        let prepared = processor.prepare_email(&job, &domain).unwrap();
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
            tags: None,
            metadata: None,
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
    /// `ProcessorError::Ses { permanent: true }` (classified in transport.rs
    /// where the typed SDK error is still available) and must take the
    /// hard-bounce path: per-recipient suppression, never a retry.
    #[test]
    fn ses_permanent_failure_classifies_hard_for_suppression() {
        let err = ProcessorError::Ses {
            permanent: true,
            message: "SES send failed: MailboxDoesNotExist".into(),
        };
        assert_eq!(classify_send_failure(&err), SendFailureClass::Hard);
    }

    /// A transient SES failure (5xx / network) carries permanent:false and
    /// must retry via the soft-bounce backoff — never suppress on it.
    #[test]
    fn ses_transient_failure_classifies_soft_for_retry() {
        let err = ProcessorError::Ses {
            permanent: false,
            message: "SES send failed: 503 Service Unavailable".into(),
        };
        assert_eq!(classify_send_failure(&err), SendFailureClass::Soft);
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

    /// The admission keys must scope BOTH dimensions: a tenant-wide bucket
    /// (account ceiling) and a per-domain bucket.
    #[test]
    fn send_admission_keys_cover_tenant_and_domain() {
        let job = tracking_gate_job();
        let keys = send_admission_keys(&job);
        assert_eq!(keys.len(), 2);
        assert!(
            keys.iter().any(|k| k.contains(&job.tenant_id)),
            "a tenant-scoped bucket must exist: {keys:?}"
        );
        assert!(
            keys.iter().any(|k| k.contains(&job.domain_id)),
            "a domain-scoped bucket must exist: {keys:?}"
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

        let keys = send_admission_keys(&tracking_gate_job());
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
        let keys_a = send_admission_keys(&job);
        job.domain_id = "domain-b".into();
        let keys_b = send_admission_keys(&job);

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
        let keys_other = send_admission_keys(&job);
        assert!(reserve_send_admission(&redis, &keys_other, 1, t0)
            .await
            .unwrap());
    }

    /// The processor-level gate consumes the plumbed config rate and defers
    /// (returns false) once it is exhausted; a 0 rate disables the gate; an
    /// unreachable Redis fails OPEN (best-effort, like the send marker).
    #[tokio::test]
    async fn check_send_admission_gates_on_config_rate_and_fails_open() {
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
                .check_send_admission(&tracking_gate_job())
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
        assert!(processor.check_send_admission(&job).await.unwrap());
        assert!(processor.check_send_admission(&job).await.unwrap());
        assert!(
            !processor.check_send_admission(&job).await.unwrap(),
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
            unlimited.check_send_admission(&job).await.unwrap(),
            "rate 0 must disable the admission gate without touching Redis"
        );
    }

    /// D: the audit `messages` row must follow the queue row: an accepted
    /// SMTP send transitions status 'queued' → 'sent' (mirroring the SES
    /// delivery-notification handler), scoped to tenant and ONLY from
    /// 'queued' so bounce/complaint states set by other paths win.
    #[test]
    fn messages_sent_update_transitions_only_queued_rows() {
        let sql = MESSAGES_SENT_UPDATE_SQL;
        assert!(
            sql.contains("SET status = 'sent'"),
            "must set the terminal sent status"
        );
        assert!(
            sql.contains("status = 'queued'"),
            "transition must be conditional on the current status"
        );
        assert!(sql.contains("tenant_id = $2"), "must be tenant-scoped");
        assert!(
            sql.contains("id = $1::uuid"),
            "must key on the message UUID"
        );
    }

    #[test]
    fn send_marker_key_is_scoped_to_row_attempt_and_recipient() {
        let job = queued_row("a@example.com", Some(vec!["a@example.com".into()]));
        let jobs = queued_row_to_jobs(job);
        let key = send_marker_key(&jobs[0]);
        assert_eq!(key, "email:send:job-1:0:a@example.com");
    }

    /// G.3c: simulate the reclaim sequence — the first claim wins, the
    /// reclaim of a lease that expired mid-send is refused, and the marker
    /// is releasable once the attempt is handled.
    // ---------------------------------------------------------------------------
    // Audit-1: real per-domain warmup state (dedicated_ips, migrations 071/093)
    // ---------------------------------------------------------------------------

    #[test]
    fn warmup_derivation_disabled_without_warming_ips() {
        // No dedicated IP in warmup (shared pool = platform reputation):
        // warmup limiting must stay off.
        let (enabled, day) = derive_domain_warmup(Utc::now(), &[]);
        assert!(!enabled, "no warming IPs => warmup disabled");
        assert_eq!(day, 0);
    }

    #[test]
    fn warmup_derivation_uses_elapsed_days_of_warming_ip() {
        let now = Utc::now();
        let (enabled, day) = derive_domain_warmup(now, &[now - chrono::Duration::days(3)]);
        assert!(enabled, "an active warmup row must enable the gate");
        assert_eq!(day, 3, "day must be the whole days since warmup_started_at");
    }

    #[test]
    fn warmup_derivation_binds_to_the_least_warmed_ip() {
        // Several warming IPs: the furthest-behind one is the binding
        // constraint on the tenant's sending reputation.
        let now = Utc::now();
        let (enabled, day) = derive_domain_warmup(
            now,
            &[
                now - chrono::Duration::days(10),
                now - chrono::Duration::days(3),
                now - chrono::Duration::days(40),
            ],
        );
        assert!(enabled);
        assert_eq!(day, 3, "MIN elapsed days across warming IPs wins");
    }

    #[test]
    fn warmup_derivation_clamps_to_day_zero() {
        // A warmup started moments ago (or a clock-skewed future timestamp)
        // is day 0, never negative.
        let now = Utc::now();
        let (enabled, day) = derive_domain_warmup(
            now,
            &[
                now + chrono::Duration::hours(1),
                now - chrono::Duration::hours(2),
            ],
        );
        assert!(enabled);
        assert_eq!(day, 0);
    }

    /// get_domain must consult the real warmup tables (dedicated_ips was
    /// given per-IP warmup state by migrations 071/093) instead of
    /// hardcoding `false AS warmup_enabled, 0 AS warmup_day`.
    #[test]
    fn get_domain_sql_consults_dedicated_ips_warmup_state() {
        assert!(
            GET_DOMAIN_SQL.contains("dedicated_ips"),
            "get_domain must read the real warmup state: {GET_DOMAIN_SQL}"
        );
        assert!(
            !GET_DOMAIN_SQL.contains("false AS warmup_enabled"),
            "the hardcoded warmup constants must be gone: {GET_DOMAIN_SQL}"
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

    /// Audit-1 behavioral gate: with warmup_enabled and warmup_day = N, the
    /// Redis counter gate blocks sends above WarmupLimits::for_day(N)'s cap
    /// and admits below it.
    #[tokio::test]
    async fn warmup_gate_blocks_above_the_days_cap() {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("skipping: cannot allocate port");
                return;
            }
        };
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = match std::process::Command::new("redis-server")
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
        {
            Ok(child) => child,
            Err(_) => {
                eprintln!("skipping: redis-server not available");
                return;
            }
        };
        let mut ready = false;
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        ready = true;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("skipping: redis-server did not become ready");
            return;
        }

        let result: ProcessorResult<()> = async {
            let db = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://localhost/unused")
                .unwrap();
            let redis = deadpool_redis::Config::from_url(format!("redis://127.0.0.1:{port}"))
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .map_err(|e| ProcessorError::Job(e.to_string()))?;
            let processor = EmailProcessor::new(db, redis, EmailConfig::default())
                .await
                .unwrap();

            let mut domain = tracking_gate_domain();
            domain.warmup_enabled = true;
            domain.warmup_day = 3; // WarmupLimits::for_day(3).daily_limit == 400
            let job = tracking_gate_job();

            // Pre-fill the shared day counter to exactly the cap: the next
            // increment exceeds it, so the gate must refuse AND roll the
            // over-limit increment back.
            let today = Utc::now().format("%Y-%m-%d").to_string();
            let key = format!("warmup:count:{}:{}", today, job.domain_id);
            {
                let mut conn = processor.redis.get().await.unwrap();
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(WarmupLimits::for_day(3).daily_limit)
                    .query_async(&mut *conn)
                    .await
                    .unwrap();
            }
            assert!(
                !processor.check_warmup_limit(&job, &domain).await.unwrap(),
                "a send above the day's cap must be blocked"
            );
            let after: i64 = {
                let mut conn = processor.redis.get().await.unwrap();
                redis::cmd("GET")
                    .arg(&key)
                    .query_async(&mut *conn)
                    .await
                    .unwrap()
            };
            assert_eq!(
                after,
                WarmupLimits::for_day(3).daily_limit,
                "the refused send must roll its increment back"
            );

            // Below the cap the gate admits.
            {
                let mut conn = processor.redis.get().await.unwrap();
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(WarmupLimits::for_day(3).daily_limit - 1)
                    .query_async(&mut *conn)
                    .await
                    .unwrap();
            }
            assert!(
                processor.check_warmup_limit(&job, &domain).await.unwrap(),
                "a send below the cap must be admitted"
            );

            // A domain without warmup state is never gated, regardless of counters.
            let cold = tracking_gate_domain();
            assert!(processor.check_warmup_limit(&job, &cold).await.unwrap());
            Ok(())
        }
        .await;
        let _ = child.kill();
        let _ = child.wait();
        result.expect("warmup gate sequence");
    }

    #[tokio::test]
    async fn send_marker_prevents_double_send_on_reclaim() {
        // Ephemeral redis-server; skip when unavailable.
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("skipping: cannot allocate port");
                return;
            }
        };
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = match std::process::Command::new("redis-server")
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
        {
            Ok(child) => child,
            Err(_) => {
                eprintln!("skipping: redis-server not available");
                return;
            }
        };
        let mut ready = false;
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        ready = true;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("skipping: redis-server did not become ready");
            return;
        }

        let result: ProcessorResult<()> = async {
            let redis = deadpool_redis::Config::from_url(format!("redis://127.0.0.1:{port}"))
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .map_err(|e| ProcessorError::Job(e.to_string()))?;
            let job = queued_row("a@example.com", Some(vec!["a@example.com".into()]));
            let job = queued_row_to_jobs(job).remove(0);

            // 1. Original worker claims the send slot.
            assert!(try_claim_send_slot(&redis, &job, 60).await.unwrap());
            // 2. Worker crashes mid-send; the row is reclaimed with the SAME
            //    attempt — the marker is still held → no double send.
            assert!(
                !try_claim_send_slot(&redis, &job, 60).await.unwrap(),
                "reclaim of an in-flight attempt must be refused"
            );
            // 3. A different recipient of the same row is independent.
            let sibling = EmailJob {
                to: "b@example.com".into(),
                ..job.clone()
            };
            assert!(try_claim_send_slot(&redis, &sibling, 60).await.unwrap());
            // 4. After the attempt is handled the marker is released.
            release_send_slot(&redis, &job).await;
            assert!(try_claim_send_slot(&redis, &job, 60).await.unwrap());
            Ok(())
        }
        .await;
        let _ = child.kill();
        let _ = child.wait();
        result.expect("marker sequence");
    }
}
