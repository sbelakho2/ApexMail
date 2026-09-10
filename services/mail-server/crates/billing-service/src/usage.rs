//! Usage tracking and metering service.
//!
//! Records metering events with idempotency via Redis dedup keys, aggregates
//! usage per billing period, and checks quotas.

use chrono::{DateTime, Datelike, Utc};
use deadpool_redis::Pool as RedisPool;
use redis::AsyncCommands;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::plans::builtin_quota_limits;
use crate::routes::append_audit_log;
use crate::types::{MeterEventType, UsageSummary};

// ---------------------------------------------------------------------------
// Canonical logical usage-operation ledger (audit F71)
// ---------------------------------------------------------------------------

/// Outcome of claiming a logical usage operation in the canonical
/// `usage_operations` ledger (migration 179).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageOperationClaim {
    /// First claim of this logical operation. `original_timestamp` is the
    /// IMMUTABLE first-claim timestamp every durable (re-)recording of the
    /// operation must use — the partitioned metering table can never hold
    /// two rows for one logical operation at different timestamps.
    Claimed { original_timestamp: DateTime<Utc> },
    /// The same logical operation with the SAME bound content was already
    /// claimed — an idempotent replay.
    Replay { original_timestamp: DateTime<Utc> },
    /// The logical id was reused with DIFFERENT content — rejected, never
    /// silently re-counted.
    Conflict,
}

/// Canonical content hash binding a logical usage operation to its
/// tenant/kind/payload (audit F71). Computed from the CALLER-supplied
/// payload only (before subscription-context enrichment, which varies
/// over time), so a genuine retry hashes identically and a divergent
/// reuse does not.
pub fn usage_payload_hash(
    tenant_id: &str,
    event_type: &str,
    quantity: i64,
    event_id: Uuid,
    metadata: Option<&serde_json::Value>,
) -> String {
    let canonical = serde_json::json!({
        "tenant": tenant_id,
        "kind": event_type,
        "quantity": quantity,
        "eventId": event_id,
        "metadata": metadata.unwrap_or(&serde_json::Value::Null),
    });
    let digest = Sha256::digest(canonical.to_string().as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Globally-unique logical operation key (audit F71): tenant + kind +
/// logical event id. The ledger's UNIQUE(operation_key) is the durable,
/// cross-process fence the Redis dedup key cannot provide.
fn usage_operation_key(tenant_id: &str, event_type: &str, event_id: Uuid) -> String {
    format!("{tenant_id}:{event_type}:{event_id}")
}

/// The SHARED operation claim API (audit F71): claims a logical usage
/// operation exactly once in the canonical ledger, on the caller's
/// transaction, BEFORE the metering row (and its quota effects) is
/// written. Both generic metering ([`record_usage`]) and send
/// reservations ([`record_with_quota_check`] — preserving F22's claim
/// ordering: Redis fast-path, reservation, then this durable fence)
/// route through it.
async fn claim_usage_operation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    event_type: &str,
    event_id: Uuid,
    quantity: i64,
    metadata: Option<&serde_json::Value>,
) -> Result<UsageOperationClaim, UsageError> {
    let payload_hash = usage_payload_hash(tenant_id, event_type, quantity, event_id, metadata);
    let operation_key = usage_operation_key(tenant_id, event_type, event_id);

    let inserted: Option<DateTime<Utc>> = sqlx::query_scalar(
        r#"
        INSERT INTO usage_operations (
            operation_key, tenant_id, event_kind, event_id, payload_hash, original_timestamp
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (operation_key) DO NOTHING
        RETURNING original_timestamp
        "#,
    )
    .bind(&operation_key)
    .bind(tenant_id)
    .bind(event_type)
    .bind(event_id)
    .bind(&payload_hash)
    .bind(Utc::now())
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(original_timestamp) = inserted {
        return Ok(UsageOperationClaim::Claimed { original_timestamp });
    }

    // Lost the race (or a retry): same content is a replay, different
    // content is a rejected reuse of the logical id.
    let existing: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT payload_hash, original_timestamp FROM usage_operations WHERE operation_key = $1",
    )
    .bind(&operation_key)
    .fetch_optional(&mut **tx)
    .await?;
    match existing {
        Some((hash, original_timestamp)) if hash == payload_hash => {
            Ok(UsageOperationClaim::Replay { original_timestamp })
        }
        Some(_) => Ok(UsageOperationClaim::Conflict),
        // Unreachable without concurrent deletion; treat conservatively as
        // a conflict so nothing is double-counted.
        None => Ok(UsageOperationClaim::Conflict),
    }
}

/// Lua script that atomically sets the dedup key and increments the counter.
/// This prevents the data race between dedup-check and counter-update that
/// existed when they were separate Redis commands.
///
/// KEYS[1] = dedup key
/// KEYS[2] = counter key
/// ARGV[1] = dedup TTL in seconds (40 days — matches the counter TTL below
///           so retries outside a 24h window still dedup)
/// ARGV[2] = quantity to increment by
/// ARGV[3] = counter TTL in seconds (40*86400)
///
/// Returns: 1 if newly recorded, 0 if duplicate.
const RECORD_USAGE_LUA: &str = r#"
    local was_set = redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX')
    if not was_set then
        return 0
    end
    redis.call('INCRBY', KEYS[2], ARGV[2])
    redis.call('EXPIRE', KEYS[2], ARGV[3])
    return 1
"#;

/// Dedup key TTL in seconds. Matches the 40-day counter TTL so a duplicate
/// event is still recognized across the whole retention window of the
/// real-time counters it would have incremented.
const DEDUP_TTL_SECS: i64 = 40 * 86_400;

/// Fix I2 — resolve a tenant's effective plan limits. An active admin plan
/// override (plan_overrides, migrations 069/093/098) wins over the tenant's
/// own plan, exactly like plans::get_plan_for_tenant. Every quota path in
/// this module (get_usage, check_quota, record_with_quota_check) reads
/// through this shared statement.
const TENANT_PLAN_LIMITS_SQL: &str = r#"
        SELECT t.plan as plan_name,
               p.email_limit,
               p.api_call_limit,
               t.created_at as tenant_created_at
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        WHERE t.id = $1
        "#;

/// Free-plan launch allowance (2026-09-08 pricing review): the standing
/// Free ceiling is 3,000 emails/month; a tenant on the FREE plan within
/// its first 30 days gets a one-time 30,000-email launch allowance
/// instead. The usage counter is anchored to the tenant's billing cycle
/// (cycle 1 == the tenant's first 30 days), so the allowance applies
/// exactly once and never refreshes. Overrides that name another plan
/// are never widened by the allowance.
pub(crate) const FREE_PLAN_LAUNCH_ALLOWANCE: i64 = 30_000;
pub(crate) const FREE_PLAN_LAUNCH_WINDOW_DAYS: i64 = 30;

fn free_launch_allowance_applies(row: &TenantPlanLimitRow) -> bool {
    if row.plan_name != "free" {
        return false;
    }
    match row.tenant_created_at {
        Some(created) => {
            let window = chrono::Duration::days(FREE_PLAN_LAUNCH_WINDOW_DAYS);
            chrono::Utc::now() - created < window
        }
        // Unknown creation date: do not widen the limit.
        None => false,
    }
}

/// Fix E — which plan limit (if any) gates a metering event type.
/// Only email and API-call quotas exist in plans.rs; the remaining metered
/// resources (bandwidth, storage, webhooks, dedicated IP hours) are recorded
/// without a quota gate (-1 = unlimited) rather than being blocked by the
/// email limit.
fn quota_limit_for_event(event_type: MeterEventType, limits: &PlanLimitRow) -> i64 {
    match event_type {
        MeterEventType::EmailsSent | MeterEventType::EmailsDelivered => limits.email_limit,
        MeterEventType::ApiCalls => limits.api_call_limit,
        MeterEventType::WebhooksDelivered
        | MeterEventType::DedicatedIpHours
        | MeterEventType::StorageGbHours
        | MeterEventType::BandwidthGb => -1,
    }
}

/// Fix I15 — month period boundaries for a tenant usage query. With no
/// timezone the historical UTC behaviour is preserved; an explicit IANA
/// timezone shifts both boundaries to local midnight (e.g. VAT-period-
/// consistent Europe/Tallinn reporting), which keeps DST months correct.
pub fn month_period_for_tz(
    now: DateTime<Utc>,
    tz: Option<&str>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    match tz.map(str::trim).filter(|value| !value.is_empty()) {
        None => {
            let month_start = now.date_naive().with_day(1).unwrap_or(now.date_naive());
            let period_start = month_start
                .and_hms_opt(0, 0, 0)
                .unwrap_or_default()
                .and_utc();
            Ok((period_start, period_start + chrono::Months::new(1)))
        }
        Some(name) => {
            let tz: chrono_tz::Tz = name
                .parse()
                .map_err(|_| format!("Unknown timezone: {name}"))?;
            let local_now = now.with_timezone(&tz);

            let mut year = local_now.year();
            let mut month = local_now.month();
            let mut period_start = local_midnight(&tz, year, month)?;

            // The current instant may still belong to the previous local
            // month's billing period if the local day is the 1st but the
            // local time is before midnight (impossible by construction —
            // period_start is the 1st 00:00), so a single boundary is enough.
            if local_now < period_start {
                month = month.saturating_sub(1);
                if month == 0 {
                    month = 12;
                    year -= 1;
                }
                period_start = local_midnight(&tz, year, month)?;
            }

            let (next_year, next_month) = if month == 12 {
                (year + 1, 1)
            } else {
                (year, month + 1)
            };
            let period_end = local_midnight(&tz, next_year, next_month)?;

            Ok((
                period_start.with_timezone(&Utc),
                period_end.with_timezone(&Utc),
            ))
        }
    }
}

fn local_midnight(
    tz: &chrono_tz::Tz,
    year: i32,
    month: u32,
) -> Result<chrono::DateTime<chrono_tz::Tz>, String> {
    use chrono::TimeZone;

    let naive = chrono::NaiveDate::from_ymd_opt(year, month, 1)
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .ok_or_else(|| format!("Invalid local midnight for {year}-{month:02}"))?;

    match tz.from_local_datetime(&naive) {
        chrono::LocalResult::Single(value) => Ok(value),
        // Midnight DST gaps (rare) resolve to the first instant after the gap.
        chrono::LocalResult::Ambiguous(earliest, _) => Ok(earliest),
        chrono::LocalResult::None => {
            let _ = naive;
            // Spring-forward gap: step forward to the first valid wall time.
            let later = naive + chrono::TimeDelta::hours(1);
            match tz.from_local_datetime(&later) {
                chrono::LocalResult::Single(value) | chrono::LocalResult::Ambiguous(value, _) => {
                    Ok(value)
                }
                chrono::LocalResult::None => Err(format!(
                    "Invalid local midnight for {year}-{month:02} in timezone"
                )),
            }
        }
    }
}

pub(crate) fn build_metering_audit_metadata(
    event_type: &str,
    quantity: i64,
    recorded_at: DateTime<Utc>,
    metadata: &serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut audit_metadata = serde_json::Map::new();
    audit_metadata.insert("eventType".into(), json!(event_type));
    audit_metadata.insert("quantity".into(), json!(quantity));
    audit_metadata.insert("recordedAt".into(), json!(recorded_at.to_rfc3339()));
    audit_metadata.insert("metadata".into(), metadata.clone());
    audit_metadata
}

/// Record a single metering event with deduplication and atomic
/// dedup + counter increment to prevent data races.
///
/// Uses a Lua script to combine the dedup key SET NX and the real-time
/// counter INCRBY into a single atomic Redis operation. If the DB insert
/// subsequently fails, the counter is rolled back via `rollback_usage_record`.
///
/// Returns `true` if the event was newly recorded, `false` if it was a
/// duplicate.
pub async fn record_usage(
    pool: &PgPool,
    redis: &RedisPool,
    tenant_id: &str,
    event_type: MeterEventType,
    quantity: i64,
    event_id: Option<Uuid>,
    metadata: Option<serde_json::Value>,
) -> Result<bool, UsageError> {
    if quantity <= 0 {
        return Err(UsageError::InvalidQuantity(quantity));
    }

    let id = event_id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let caller_metadata = metadata.clone();
    let meta = enrich_usage_metadata(pool, tenant_id, now, metadata).await?;
    let cycle_anchor = tenant_cycle_anchor(pool, tenant_id, now).await;

    // 1. Persist to DB and append an immutable audit record in the same
    //    transaction. metering_events is RANGE-partitioned by "timestamp"
    //    with PRIMARY KEY (id, timestamp), so the ON CONFLICT arbiter must
    //    include the partition key (a bare (id) arbiter is 42P10).
    //
    //    Audit F71: the check-then-insert existence race is closed by
    //    claiming the logical operation in the canonical usage_operations
    //    ledger FIRST, in the SAME transaction. The claim fixes the
    //    IMMUTABLE original timestamp, so two attempts carrying the same
    //    logical id at different wall-clock times can never produce two
    //    metering rows (quantity counted twice); a divergent reuse of the
    //    id is rejected outright.
    let mut tx = pool.begin().await.map_err(UsageError::Db)?;
    let event_type_str = event_type_to_str(event_type);
    // Ok(true) = a NEW metering row was written; Ok(false) = ledger replay
    // (the row already exists — the Redis dedup key is republished instead
    // of re-running the counter EVAL, which would otherwise double-count
    // after a Redis flush).
    let audit_result: Result<bool, UsageError> = async {
        match claim_usage_operation_in_tx(
            &mut tx,
            tenant_id,
            event_type_str,
            id,
            quantity,
            caller_metadata.as_ref(),
        )
        .await?
        {
            UsageOperationClaim::Claimed { original_timestamp } => {
                let recorded_at = original_timestamp;
                sqlx::query(
                    r#"
                    INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (id, "timestamp") DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(tenant_id)
                .bind(event_type_str)
                .bind(quantity)
                .bind(recorded_at)
                .bind(&meta)
                .execute(&mut *tx)
                .await
                .map_err(UsageError::Db)?;

                append_audit_log(
                    &mut tx,
                    tenant_id,
                    "billing.metering_event_recorded",
                    "metering_event",
                    Some(&id.to_string()),
                    serde_json::Value::Object(build_metering_audit_metadata(
                        event_type_str,
                        quantity,
                        recorded_at,
                        &meta,
                    )),
                    recorded_at,
                )
                .await
                .map_err(UsageError::Audit)?;

                tx.commit().await.map_err(UsageError::Db)?;
                Ok(true)
            }
            UsageOperationClaim::Replay { .. } => {
                // The durable row exists (or a concurrent writer is
                // committing it under the same claim); nothing to insert
                // or audit.
                tx.commit().await.map_err(UsageError::Db)?;
                Ok(false)
            }
            UsageOperationClaim::Conflict => Err(UsageError::OperationConflict {
                event_id: id,
                detail: "usage operation id reused with different tenant/kind/payload".into(),
            }),
        }
    }
    .await;

    // 2. Atomically set dedup key and bump real-time Redis counter.
    //    Using a Lua script prevents the data race between the dedup check
    //    and counter increment that would exist with separate commands.
    //    The counter key follows the tenant's BILLING CYCLE when a
    //    subscription defines one, matching the quota gate and the
    //    /usage report period semantics.
    let dedup_key = usage_dedup_key(id);
    let period_key = usage_counter_key_anchored(tenant_id, event_type, now, cycle_anchor);
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;

    // DB outcome (audit F71): a ledger REPLAY whose Redis dedup key is
    // still present EVALs to 0 below (duplicate). If the key was lost
    // (Redis flush / post-commit compensation), the EVAL re-publishes it
    // and restores the real-time counter — the durable ledger keeps the
    // billing-side exactly-once either way.
    let _newly_recorded = audit_result?;

    // Execute the atomic Lua script: SET NX dedup + INCRBY counter.
    // Fix F8 — on a post-commit Redis failure the DB row is already durable
    // but the transport-level error leaves the counter/dedup state unknown
    // (the Lua itself is atomic, so it either ran completely or not at all).
    // Perform the SAME compensation `record_with_quota_check` performs on
    // its failure path: decrement the counter by the attempted quantity and
    // drop the dedup key, returning Redis to its pre-call state so a retry
    // re-records cleanly. The committed `metering_events` row stays — it is
    // the source of truth for /usage aggregates and the DB fallback path of
    // `check_quota`.
    let recorded: i64 = match redis::cmd("EVAL")
        .arg(RECORD_USAGE_LUA)
        .arg(2) // number of keys
        .arg(&dedup_key)
        .arg(&period_key)
        .arg(DEDUP_TTL_SECS) // dedup TTL (40 days)
        .arg(quantity)
        .arg(40i64 * 86_400i64) // counter TTL (40 days)
        .query_async(&mut conn)
        .await
    {
        Ok(recorded) => recorded,
        Err(error) => {
            if let Err(rollback_error) =
                rollback_quota_reservation(pool, redis, tenant_id, event_type, quantity, id, now)
                    .await
            {
                tracing::error!(
                    error = %rollback_error,
                    tenant_id,
                    event_id = %id,
                    "failed to compensate Redis counter after metering EVAL failure"
                );
            }
            return Err(UsageError::RedisCmd(error));
        }
    };

    if recorded == 0 {
        // Dedup key already existed — this is a duplicate event that somehow
        // made it past the DB ON CONFLICT. This is not expected but harmless.
        return Ok(false);
    }

    Ok(true)
}

/// Aggregate usage for a tenant in a billing period.
pub async fn get_usage(
    pool: &PgPool,
    tenant_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<UsageSummary, UsageError> {
    let rows: Vec<UsageAggRow> = sqlx::query_as(
        r#"
        SELECT event_type, SUM(quantity)::bigint as total
        FROM metering_events
        WHERE tenant_id = $1
          AND timestamp >= $2
          AND timestamp <  $3
        GROUP BY event_type
        "#,
    )
    .bind(tenant_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_all(pool)
    .await
    .map_err(UsageError::Db)?;

    let mut emails_sent: i64 = 0;
    let mut api_calls: i64 = 0;
    let mut metrics = serde_json::Map::new();

    for row in &rows {
        let qty = row.total.unwrap_or(0);
        metrics.insert(row.event_type.clone(), json!(qty));
        match row.event_type.as_str() {
            "emails_sent" => emails_sent = qty,
            "api_calls" => api_calls = qty,
            _ => {}
        }
    }

    // Look up plan limits (override-aware — Fix I2).
    let limits: Option<TenantPlanLimitRow> = sqlx::query_as(TENANT_PLAN_LIMITS_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(UsageError::Db)?;

    let resolved_limits = resolve_plan_limits(limits);
    let emails_limit = resolved_limits.email_limit;
    let api_calls_limit = resolved_limits.api_call_limit;

    let percent_used = if emails_limit > 0 {
        (emails_sent as f64 / emails_limit as f64) * 100.0
    } else {
        0.0
    };

    Ok(UsageSummary {
        tenant_id: tenant_id.to_string(),
        period_start,
        period_end,
        emails_sent,
        emails_limit,
        api_calls,
        api_calls_limit,
        percent_used,
        metrics: serde_json::Value::Object(metrics),
    })
}

/// Check whether a tenant has exceeded their email quota for the current
/// billing period.
pub async fn check_quota(
    pool: &PgPool,
    redis: &RedisPool,
    tenant_id: &str,
) -> Result<QuotaStatus, UsageError> {
    // Fast-path:read the real-time Redis counter for the current BILLING
    // CYCLE (UTC calendar month only for tenants without a subscription —
    // the gate and the /usage report must agree on the period).
    let now = Utc::now();
    let cycle_anchor = tenant_cycle_anchor(pool, tenant_id, now).await;
    let counter_key =
        usage_counter_key_anchored(tenant_id, MeterEventType::EmailsSent, now, cycle_anchor);

    // that metering is degraded rather than completely broken.
    let current = match redis.get().await {
        Ok(mut conn) => {
            let val: Option<i64> = conn.get(&counter_key).await.map_err(UsageError::RedisCmd)?;
            val.unwrap_or(0)
        }
        Err(e) => {
            tracing::warn!(error = %e, tenant_id, "Redis unavailable for quota check — falling back to DB aggregate");
            // Fix F3 — the fallback must aggregate over the SAME period the
            // enforced counter covers: the tenant's anchored billing cycle
            // when a subscription defines one, NOT the UTC calendar month
            // (otherwise an anchored tenant got a fresh quota window in the
            // fallback for the days between the calendar month start and
            // the cycle start).
            let period_start = match cycle_anchor {
                Some(anchor) => most_recent_anchored_cycle(now, anchor).2,
                None => now
                    .date_naive()
                    .with_day(1)
                    .unwrap_or(now.date_naive())
                    .and_hms_opt(0, 0, 0)
                    .unwrap_or_default()
                    .and_utc(),
            };

            let row: Option<(Option<i64>,)> = sqlx::query_as(
                r#"
                SELECT SUM(quantity)::bigint
                FROM metering_events
                WHERE tenant_id = $1
                  AND event_type = 'emails_sent'
                  AND timestamp >= $2
                "#,
            )
            .bind(tenant_id)
            .bind(period_start)
            .fetch_optional(pool)
            .await
            .map_err(UsageError::Db)?;
            row.and_then(|r| r.0).unwrap_or(0)
        }
    };

    let limits: Option<TenantPlanLimitRow> = sqlx::query_as(TENANT_PLAN_LIMITS_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(UsageError::Db)?;

    let limit = resolve_plan_limits(limits).email_limit;

    if limit < 0 {
        // Unlimited plan.
        return Ok(QuotaStatus {
            allowed: true,
            current,
            limit: -1,
            percent_used: 0.0,
        });
    }

    let pct = if limit > 0 {
        (current as f64 / limit as f64) * 100.0
    } else {
        100.0
    };

    Ok(QuotaStatus {
        allowed: current < limit,
        current,
        limit,
        percent_used: pct,
    })
}

/// Reset the real-time Redis counters for a tenant (typically at billing-cycle
/// rollover).
///
/// Both counter-key shapes are cleared: the plain calendar-month label
/// (`...:{Y}-{M}`) and the ANCHORED billing-cycle label
/// (`...:c{Y}-{M}` — see [`usage_counter_key_anchored`]). The anchored
/// pattern was previously missed, so subscription tenants kept stale
/// counters after a reset for the very cycle the reset was meant to clear.
pub async fn reset_monthly_counters(
    redis: &RedisPool,
    tenant_id: &str,
    year: i32,
    month: u32,
) -> Result<(), UsageError> {
    let patterns = [
        format!("meter:rt:{tenant_id}:*:{year}-{month:02}"),
        format!("meter:rt:{tenant_id}:*:c{year}-{month:02}"),
    ];
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;

    // Use SCAN instead of KEYS for production safety — KEYS blocks Redis.
    let mut all_keys: Vec<String> = Vec::new();
    for pattern in &patterns {
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(UsageError::RedisCmd)?;
            all_keys.extend(batch);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
    }

    if !all_keys.is_empty() {
        let _: () = redis::cmd("DEL")
            .arg(&all_keys)
            .query_async(&mut conn)
            .await
            .map_err(UsageError::RedisCmd)?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct MeteringSubscriptionContext {
    subscription_id: String,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct MeteringSubscriptionContextRow {
    subscription_id: String,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
}

async fn enrich_usage_metadata(
    pool: &PgPool,
    tenant_id: &str,
    recorded_at: DateTime<Utc>,
    metadata: Option<serde_json::Value>,
) -> Result<serde_json::Value, UsageError> {
    let metadata = normalize_usage_metadata(metadata);
    if metadata.contains_key("subscriptionId") {
        return Ok(serde_json::Value::Object(metadata));
    }

    let context = load_metering_subscription_context(pool, tenant_id, recorded_at).await?;
    Ok(attach_subscription_context(metadata, context.as_ref()))
}

async fn load_metering_subscription_context(
    pool: &PgPool,
    tenant_id: &str,
    recorded_at: DateTime<Utc>,
) -> Result<Option<MeteringSubscriptionContext>, UsageError> {
    // Fix C — subscription state is written exclusively by the Stripe
    // webhook handlers into stripe_subscriptions; the legacy `subscriptions`
    // table is never populated, so enrichment must read stripe_subscriptions.
    let matched = sqlx::query_as::<_, MeteringSubscriptionContextRow>(
        r#"
        SELECT stripe_subscription_id AS subscription_id,
               billing_cycle_start AS period_start,
               billing_cycle_end AS period_end
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
          AND billing_cycle_start <= $2
          AND billing_cycle_end > $2
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(recorded_at)
    .fetch_optional(pool)
    .await
    .map_err(UsageError::Db)?;

    let fallback = if matched.is_none() {
        sqlx::query_as::<_, MeteringSubscriptionContextRow>(
            r#"
            SELECT stripe_subscription_id AS subscription_id,
                   billing_cycle_start AS period_start,
                   billing_cycle_end AS period_end
            FROM stripe_subscriptions
            WHERE tenant_id = $1
              AND status IN ('active', 'trialing', 'past_due')
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(UsageError::Db)?
    } else {
        None
    };

    Ok(matched.or(fallback).map(|row| MeteringSubscriptionContext {
        subscription_id: row.subscription_id,
        period_start: row.period_start,
        period_end: row.period_end,
    }))
}

fn normalize_usage_metadata(
    metadata: Option<serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    match metadata {
        Some(serde_json::Value::Object(map)) => map,
        Some(value) => {
            let mut map = serde_json::Map::new();
            map.insert("value".into(), value);
            map
        }
        None => serde_json::Map::new(),
    }
}

fn attach_subscription_context(
    mut metadata: serde_json::Map<String, serde_json::Value>,
    context: Option<&MeteringSubscriptionContext>,
) -> serde_json::Value {
    if let Some(context) = context {
        metadata
            .entry("subscriptionId")
            .or_insert_with(|| json!(context.subscription_id));
        metadata
            .entry("subscriptionPeriodStart")
            .or_insert_with(|| json!(context.period_start.to_rfc3339()));
        metadata
            .entry("subscriptionPeriodEnd")
            .or_insert_with(|| json!(context.period_end.to_rfc3339()));
    }

    serde_json::Value::Object(metadata)
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Lua script for atomic quota check-and-increment in Redis.
/// KEYS[1] = counter key (e.g. "meter:rt:<tenant>:emails_sent:2026-03")
/// ARGV[1] = plan limit (-1 = unlimited)
/// ARGV[2] = quantity to increment
/// ARGV[3] = TTL in seconds for the counter key
/// Returns:new counter value on success, -1 if quota exceeded.
const QUOTA_CHECK_AND_INCR_LUA: &str = r#"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local lim     = tonumber(ARGV[1])
local qty     = tonumber(ARGV[2])
local ttl     = tonumber(ARGV[3])
if lim >= 0 and current + qty > lim then
    return -1
end
local new_val = redis.call('INCRBY', KEYS[1], qty)
redis.call('EXPIRE', KEYS[1], ttl)
return new_val
"#;

/// Atomically check the quota and record a metering event in a single
/// operation. Unlike the separate `check_quota` → `record_usage` workflow,
/// this avoids the TOCTOU window between the quota look-up and the counter
/// increment by executing a Lua script inside Redis.
/// Returns `Ok(QuotaRecordResult)` with `allowed = true` and the new counter
/// value when the event is recorded, or `allowed = false` when the quota
/// would be exceeded (counter is NOT incremented in that case).
/// Duplicates (same `event_id`) are silently de-duplicated and return
/// `QuotaRecordResult { allowed:true, current:<unchanged>, duplicate:true }`.
pub async fn record_with_quota_check(
    pool: &PgPool,
    redis: &RedisPool,
    tenant_id: &str,
    event_type: MeterEventType,
    quantity: i64,
    event_id: Option<Uuid>,
    metadata: Option<serde_json::Value>,
) -> Result<QuotaRecordResult, UsageError> {
    if quantity <= 0 {
        return Err(UsageError::InvalidQuantity(quantity));
    }

    let id = event_id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let caller_metadata = metadata.clone();
    let meta = enrich_usage_metadata(pool, tenant_id, now, metadata).await?;
    // Billing-cycle period key (see record_usage): the reservation gate, the
    // fast-path read here, and the rollback must all derive the SAME key or
    // reservations split across two counters at a cycle boundary.
    let cycle_anchor = tenant_cycle_anchor(pool, tenant_id, now).await;

    let dedup_key = usage_dedup_key(id);
    let counter_key = usage_counter_key_anchored(tenant_id, event_type, now, cycle_anchor);
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;

    // 1. Read-only dedup fast path. The dedup key is only *set* after the DB
    //    row is durably persisted (Fix I11): a crash between reservation and
    //    persist used to leave a dedup key with no DB row, permanently
    //    swallowing the event on retry.
    let already_recorded: Option<String> = conn.get(&dedup_key).await.unwrap_or(None);
    if already_recorded.is_some() {
        let current: i64 = conn.get(&counter_key).await.unwrap_or(0);
        return Ok(QuotaRecordResult {
            allowed: true,
            current,
            duplicate: true,
        });
    }

    // 2. Fetch plan limits from Postgres (override-aware) and select the
    //    quota for this event type (Fix E — API calls are no longer gated by
    //    the email limit; unmetered types are unlimited).
    let limit_row: Option<TenantPlanLimitRow> = sqlx::query_as(TENANT_PLAN_LIMITS_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(UsageError::Db)?;

    let limit = quota_limit_for_event(event_type, &resolve_plan_limits(limit_row));

    // Overage soft ceiling: email sending on an ACTIVE PAID subscription is
    // not hard-blocked at the plan limit — the published behaviour lets the
    // tenant send into an overage allowance (default 200% of the included
    // volume) with the excess invoiced at period end by the overage sweep.
    // Everything else (API calls, free plan, cancelled subscriptions,
    // unlimited plans) keeps the raw limit.
    let quota_for_gate = if matches!(event_type, MeterEventType::EmailsSent) && limit >= 0 {
        let active_paid =
            crate::overage::tenant_has_active_paid_subscription(pool, tenant_id).await?;
        crate::overage::effective_email_quota(limit, active_paid)
    } else {
        limit
    };

    // 3. Atomic check-and-increment via Lua. This is a *reservation*: if a
    //    later step fails, rollback_quota_reservation() compensates.
    let ttl_seconds: i64 = 40 * 86_400; // 40 days

    let new_val: i64 = redis::Script::new(QUOTA_CHECK_AND_INCR_LUA)
        .key(&counter_key)
        .arg(quota_for_gate)
        .arg(quantity)
        .arg(ttl_seconds)
        .invoke_async(&mut conn)
        .await
        .map_err(UsageError::RedisCmd)?;

    if new_val < 0 {
        return Ok(QuotaRecordResult {
            allowed: false,
            current: new_val,
            duplicate: false,
        });
    }

    // 4. Persist to DB and append an immutable audit record in the same
    //    transaction. Audit F71: the logical operation is claimed in the
    //    canonical usage_operations ledger FIRST, inside this transaction —
    //    the claim binds tenant/kind/payload (divergent reuse is rejected)
    //    and fixes the IMMUTABLE original timestamp, so the partitioned
    //    metering table's (id, timestamp) uniqueness fences the row exactly
    //    (two attempts of one logical operation at different wall-clock
    //    times can never count twice). Send reservations (F22's
    //    deterministic event ids) route through the SAME claim API, keeping
    //    the reservation-then-durable-fence ordering.
    let mut tx = pool.begin().await.map_err(UsageError::Db)?;
    let event_type_str = event_type_to_str(event_type);
    let persist_result: Result<bool, UsageError> = async {
        match claim_usage_operation_in_tx(
            &mut tx,
            tenant_id,
            event_type_str,
            id,
            quantity,
            caller_metadata.as_ref(),
        )
        .await?
        {
            UsageOperationClaim::Claimed { original_timestamp } => {
                let recorded_at = original_timestamp;
                let inserted = sqlx::query(
                    r#"
                    INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (id, "timestamp") DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(tenant_id)
                .bind(event_type_str)
                .bind(quantity)
                .bind(recorded_at)
                .bind(&meta)
                .execute(&mut *tx)
                .await
                .map_err(UsageError::Db)?;

                append_audit_log(
                    &mut tx,
                    tenant_id,
                    "billing.metering_event_recorded",
                    "metering_event",
                    Some(&id.to_string()),
                    serde_json::Value::Object(build_metering_audit_metadata(
                        event_type_str,
                        quantity,
                        recorded_at,
                        &meta,
                    )),
                    recorded_at,
                )
                .await
                .map_err(UsageError::Audit)?;

                tx.commit().await.map_err(UsageError::Db)?;
                Ok(inserted.rows_affected() > 0)
            }
            UsageOperationClaim::Replay { .. } => {
                tx.commit().await.map_err(UsageError::Db)?;
                Ok(false)
            }
            UsageOperationClaim::Conflict => Err(UsageError::OperationConflict {
                event_id: id,
                detail: "usage operation id reused with different tenant/kind/payload".into(),
            }),
        }
    }
    .await;

    match persist_result {
        Ok(newly_recorded) => {
            if !newly_recorded {
                // Duplicate replay that raced past the Redis fast path:
                // compensate the reservation and mark the dedup key so the
                // next replay short-circuits in step 1.
                rollback_quota_reservation(pool, redis, tenant_id, event_type, quantity, id, now)
                    .await?;
                let _: () = conn
                    .set_ex(&dedup_key, "1", dedup_ttl_secs())
                    .await
                    .unwrap_or(());
                return Ok(QuotaRecordResult {
                    allowed: true,
                    current: new_val,
                    duplicate: true,
                });
            }

            // 5. Persisted — now (and only now) publish the dedup key.
            let _: () = redis::cmd("SET")
                .arg(&dedup_key)
                .arg("1")
                .arg("EX")
                .arg(DEDUP_TTL_SECS)
                .arg("NX")
                .query_async(&mut conn)
                .await
                .unwrap_or(());

            Ok(QuotaRecordResult {
                allowed: true,
                current: new_val,
                duplicate: false,
            })
        }
        Err(error) => {
            // Persist failed — compensate the counter reservation so Redis
            // stays consistent with the DB.
            if let Err(rollback_error) =
                rollback_quota_reservation(pool, redis, tenant_id, event_type, quantity, id, now)
                    .await
            {
                tracing::error!(
                    error = %rollback_error,
                    tenant_id,
                    event_id = %id,
                    "failed to roll back quota reservation after metering DB insert failure"
                );
            }

            Err(error)
        }
    }
}

pub async fn rollback_usage_record(
    pool: &PgPool,
    redis: &RedisPool,
    tenant_id: &str,
    event_type: MeterEventType,
    quantity: i64,
    event_id: Uuid,
    recorded_at: DateTime<Utc>,
) -> Result<(), UsageError> {
    let mut tx = pool.begin().await.map_err(UsageError::Db)?;
    let rolled_back_at = Utc::now();

    sqlx::query("DELETE FROM metering_events WHERE id = $1")
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(UsageError::Db)?;

    let mut audit_metadata = build_metering_audit_metadata(
        event_type_to_str(event_type),
        quantity,
        recorded_at,
        &serde_json::Value::Null,
    );
    audit_metadata.insert("rolledBackAt".into(), json!(rolled_back_at.to_rfc3339()));

    append_audit_log(
        &mut tx,
        tenant_id,
        "billing.metering_event_rolled_back",
        "metering_event",
        Some(&event_id.to_string()),
        serde_json::Value::Object(audit_metadata),
        rolled_back_at,
    )
    .await
    .map_err(UsageError::Audit)?;

    tx.commit().await.map_err(UsageError::Db)?;

    rollback_quota_reservation(
        pool,
        redis,
        tenant_id,
        event_type,
        quantity,
        event_id,
        recorded_at,
    )
    .await
}

#[derive(sqlx::FromRow)]
struct UsageAggRow {
    event_type: String,
    total: Option<i64>,
}

#[derive(Debug, Clone)]
struct PlanLimitRow {
    email_limit: i64,
    api_call_limit: i64,
}

#[derive(sqlx::FromRow)]
struct TenantPlanLimitRow {
    plan_name: String,
    email_limit: Option<i64>,
    api_call_limit: Option<i64>,
    tenant_created_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn resolve_plan_limits(row: Option<TenantPlanLimitRow>) -> PlanLimitRow {
    match row {
        Some(row) => {
            let (fallback_email_limit, fallback_api_call_limit) =
                builtin_quota_limits(Some(&row.plan_name));

            let mut email_limit = row.email_limit.unwrap_or(fallback_email_limit);
            // Launch allowance (see FREE_PLAN_LAUNCH_ALLOWANCE): only ever
            // WIDENS the free ceiling, and only during the first 30 days —
            // an override that already grants more keeps its value.
            if free_launch_allowance_applies(&row) {
                email_limit = email_limit.max(FREE_PLAN_LAUNCH_ALLOWANCE);
            }
            PlanLimitRow {
                email_limit,
                api_call_limit: row.api_call_limit.unwrap_or(fallback_api_call_limit),
            }
        }
        None => PlanLimitRow {
            email_limit: 0,
            api_call_limit: 0,
        },
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuotaStatus {
    pub allowed: bool,
    pub current: i64,
    pub limit: i64,
    pub percent_used: f64,
}

/// Result of an atomic quota-check + record operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QuotaRecordResult {
    /// Whether the event was allowed (quota not exceeded).
    pub allowed: bool,
    /// Current counter value after the operation.
    pub current: i64,
    /// Whether this was a duplicate event (already idempotently processed).
    pub duplicate: bool,
}

fn event_type_to_str(et: MeterEventType) -> &'static str {
    meter_event_type_str(et)
}

/// Public re-export of the wire string for a metering event type (used by
/// the ingest API error paths and external callers).
pub fn meter_event_type_str(et: MeterEventType) -> &'static str {
    match et {
        MeterEventType::EmailsSent => "emails_sent",
        MeterEventType::EmailsDelivered => "emails_delivered",
        MeterEventType::ApiCalls => "api_calls",
        MeterEventType::WebhooksDelivered => "webhooks_delivered",
        MeterEventType::DedicatedIpHours => "dedicated_ip_hours",
        MeterEventType::StorageGbHours => "storage_gb_hours",
        MeterEventType::BandwidthGb => "bandwidth_gb",
    }
}

fn usage_dedup_key(event_id: Uuid) -> String {
    format!("meter:dedup:{event_id}")
}

/// Dedup TTL clamped to the SET EX argument range (seconds).
fn dedup_ttl_secs() -> u64 {
    u64::try_from(DEDUP_TTL_SECS).unwrap_or(u32::MAX as u64)
}

fn usage_counter_key(tenant_id: &str, event_type: MeterEventType, at: DateTime<Utc>) -> String {
    format!(
        "meter:rt:{}:{}:{}-{:02}",
        tenant_id,
        event_type_to_str(event_type),
        at.year(),
        at.month()
    )
}

/// Billing-cycle-aware counter key. When the tenant's subscription cycle
/// anchor (the day-of-month the cycle started) is known, the counter period
/// is labeled by the CYCLE start month, not the UTC calendar month — a
/// cycle starting on the 15th must not hand the tenant a fresh quota on the
/// 1st, and the Redis counter must agree with the tz/billing-cycle-aware
/// `/usage` report about which events belong to the current period.
fn usage_counter_key_anchored(
    tenant_id: &str,
    event_type: MeterEventType,
    at: DateTime<Utc>,
    cycle_anchor: Option<chrono::NaiveDate>,
) -> String {
    let Some(anchor) = cycle_anchor else {
        return usage_counter_key(tenant_id, event_type, at);
    };
    let (year, month, _cycle_start) = most_recent_anchored_cycle(at, anchor);
    format!(
        "meter:rt:{}:{}:c{}-{:02}",
        tenant_id,
        event_type_to_str(event_type),
        year,
        month
    )
}

/// The most recent anchored billing-cycle start at or before `at`, as
/// `(cycle_year, cycle_month, cycle_start_utc)`. Walks back month-by-month
/// from `at` to the most recent anchored cycle start (same day-of-month;
/// clamped to the month's length so a 31st anchor still fires in shorter
/// months — mirroring Stripe's own cycle proration semantics closely enough
/// for a period LABEL). Shared by the counter-key builder, the Redis-outage
/// fallback window (Fix F3) and the exported key helper (Fix F6) so every
/// path agrees on the period in force.
fn most_recent_anchored_cycle(
    at: DateTime<Utc>,
    anchor: chrono::NaiveDate,
) -> (i32, u32, DateTime<Utc>) {
    let mut year = at.year();
    let mut month = at.month();
    loop {
        let candidate = anchored_date(year, month, anchor.day());
        let candidate_start = candidate
            .and_hms_opt(0, 0, 0)
            .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
        if let Some(start) = candidate_start {
            if start <= at {
                return (year, month, start);
            }
        }
        if month == 1 {
            month = 12;
            year -= 1;
        } else {
            month -= 1;
        }
    }
}

fn anchored_date(year: i32, month: u32, day: u32) -> chrono::NaiveDate {
    let last_day = {
        let next = if month == 12 {
            chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
        }
        .expect("first of next month is always valid");
        (next - chrono::Duration::days(1)).day()
    };
    chrono::NaiveDate::from_ymd_opt(year, month, day.min(last_day))
        .expect("clamped day is always valid")
}

/// The tenant's billing-cycle anchor date (most recent cycle start at or
/// before `at`), when an active/trialing/past-due Stripe subscription
/// defines one.
async fn tenant_cycle_anchor(
    pool: &PgPool,
    tenant_id: &str,
    at: DateTime<Utc>,
) -> Option<chrono::NaiveDate> {
    sqlx::query_scalar::<_, chrono::NaiveDate>(
        r#"
        SELECT billing_cycle_start
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
          AND billing_cycle_start IS NOT NULL
        ORDER BY billing_cycle_start DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(at)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// The exact Redis real-time counter key currently ENFORCED for a tenant —
/// the one and only key the quota gate ([`record_with_quota_check`]), the
/// rollback path ([`rollback_usage_record`]) and the pending-event drain all
/// increment.
///
/// * Tenant with an active/trialing/past-due Stripe subscription (cycle
///   anchor known): the billing-cycle-anchored key
///   `meter:rt:{tenant}:{event_type}:c{year}-{month:02}`, where `(year,
///   month)` labels the month the CURRENT cycle started in.
/// * Otherwise: the legacy UTC calendar-month key
///   `meter:rt:{tenant}:{event_type}:{year}-{month:02}`.
///
/// Exported (audit F6) so external readers — api-server's
/// `/usage/realtime` — read the counter the quota gate actually enforces
/// instead of re-deriving (and drifting from) the key shape. Pass the same
/// instant you consider "now" for the read.
pub async fn enforced_counter_key(
    pool: &PgPool,
    tenant_id: &str,
    event_type: MeterEventType,
    at: DateTime<Utc>,
) -> String {
    let cycle_anchor = tenant_cycle_anchor(pool, tenant_id, at).await;
    usage_counter_key_anchored(tenant_id, event_type, at, cycle_anchor)
}

/// String-typed variant of [`enforced_counter_key`] for callers inside this
/// crate that hold the RAW wire event type (the pending-metering drain in
/// maintenance.rs recovers events whose `event_type` arrives as an
/// untyped string). Identical anchoring math; the event-type string is
/// embedded verbatim so unknown/custom types keep their counter identity.
pub(crate) async fn enforced_counter_key_for_event_type(
    pool: &PgPool,
    tenant_id: &str,
    event_type: &str,
    at: DateTime<Utc>,
) -> String {
    match tenant_cycle_anchor(pool, tenant_id, at).await {
        Some(anchor) => {
            let (year, month, _cycle_start) = most_recent_anchored_cycle(at, anchor);
            format!("meter:rt:{tenant_id}:{event_type}:c{year}-{month:02}")
        }
        None => format!(
            "meter:rt:{tenant_id}:{event_type}:{}-{:02}",
            at.year(),
            at.month()
        ),
    }
}

async fn rollback_quota_reservation(
    pool: &PgPool,
    redis: &RedisPool,
    tenant_id: &str,
    event_type: MeterEventType,
    quantity: i64,
    event_id: Uuid,
    recorded_at: DateTime<Utc>,
) -> Result<(), UsageError> {
    let cycle_anchor = tenant_cycle_anchor(pool, tenant_id, recorded_at).await;
    let counter_key = usage_counter_key_anchored(tenant_id, event_type, recorded_at, cycle_anchor);
    let dedup_key = usage_dedup_key(event_id);
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;

    let _: () = redis::pipe()
        .atomic()
        .cmd("INCRBY")
        .arg(&counter_key)
        .arg(-quantity)
        .ignore()
        .cmd("DEL")
        .arg(&dedup_key)
        .ignore()
        .query_async(&mut conn)
        .await
        .map_err(UsageError::RedisCmd)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("audit error: {0}")]
    Audit(String),
    #[error("redis pool error: {0}")]
    Redis(#[from] deadpool_redis::PoolError),
    #[error("redis command error: {0}")]
    RedisCmd(#[from] redis::RedisError),
    #[error("quantity must be positive, got {0}")]
    InvalidQuantity(i64),
    /// Audit F71: a logical usage operation id was reused with different
    /// tenant/kind/payload content — rejected instead of re-counted.
    #[error("usage operation {event_id} conflict: {detail}")]
    OperationConflict { event_id: Uuid, detail: String },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_str_mapping() {
        assert_eq!(event_type_to_str(MeterEventType::EmailsSent), "emails_sent");
        assert_eq!(event_type_to_str(MeterEventType::ApiCalls), "api_calls");
        assert_eq!(
            event_type_to_str(MeterEventType::BandwidthGb),
            "bandwidth_gb"
        );
    }

    #[test]
    fn quota_status_serialization() {
        let qs = QuotaStatus {
            allowed: true,
            current: 1_500,
            limit: 3_000,
            percent_used: 50.0,
        };
        let json = serde_json::to_value(&qs).unwrap();
        assert_eq!(json["allowed"], true);
        assert_eq!(json["current"], 1_500);
    }

    #[test]
    fn quota_status_exceeded() {
        let qs = QuotaStatus {
            allowed: false,
            current: 3_500,
            limit: 3_000,
            percent_used: 116.67,
        };
        assert!(!qs.allowed);
        assert!(qs.percent_used > 100.0);
    }

    #[test]
    fn resolve_plan_limits_prefers_database_values() {
        let limits = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "pro".to_string(),
            email_limit: Some(250_000),
            api_call_limit: Some(3_000_000),
            tenant_created_at: Some(chrono::Utc::now() - chrono::Duration::days(3)),
        }));

        assert_eq!(limits.email_limit, 250_000);
        assert_eq!(limits.api_call_limit, 3_000_000);
    }

    #[test]
    fn resolve_plan_limits_fall_back_to_builtin_plan_defaults() {
        // Outside the 30-day launch window: the standing Free ceiling.
        let limits = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "free".to_string(),
            email_limit: None,
            api_call_limit: None,
            tenant_created_at: Some(chrono::Utc::now() - chrono::Duration::days(45)),
        }));

        assert_eq!(limits.email_limit, 3_000);
        assert_eq!(limits.api_call_limit, 30_000);
    }

    #[test]
    fn free_launch_allowance_widens_only_the_first_30_days() {
        // Inside the window: widened to the one-time 30k allowance.
        let fresh = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "free".to_string(),
            email_limit: Some(3_000),
            api_call_limit: Some(30_000),
            tenant_created_at: Some(chrono::Utc::now() - chrono::Duration::days(29)),
        }));
        assert_eq!(fresh.email_limit, FREE_PLAN_LAUNCH_ALLOWANCE);
        assert_eq!(
            fresh.api_call_limit, 30_000,
            "allowance never touches API limit"
        );

        // Day 31: back to the standing ceiling.
        let aged = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "free".to_string(),
            email_limit: Some(3_000),
            api_call_limit: Some(30_000),
            tenant_created_at: Some(chrono::Utc::now() - chrono::Duration::days(31)),
        }));
        assert_eq!(aged.email_limit, 3_000);

        // Unknown creation date: never widened.
        let unknown = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "free".to_string(),
            email_limit: Some(3_000),
            api_call_limit: Some(30_000),
            tenant_created_at: None,
        }));
        assert_eq!(unknown.email_limit, 3_000);

        // A paid plan is never widened by the free allowance.
        let pro = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "pro".to_string(),
            email_limit: Some(150_000),
            api_call_limit: Some(2_000_000),
            tenant_created_at: Some(chrono::Utc::now()),
        }));
        assert_eq!(pro.email_limit, 150_000);

        // An override granting more than the allowance keeps its value.
        let boosted = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "free".to_string(),
            email_limit: Some(50_000),
            api_call_limit: Some(500_000),
            tenant_created_at: Some(chrono::Utc::now() - chrono::Duration::days(1)),
        }));
        assert_eq!(boosted.email_limit, 50_000);
    }

    #[test]
    fn resolve_plan_limits_keep_missing_tenants_denied() {
        let limits = resolve_plan_limits(None);

        assert_eq!(limits.email_limit, 0);
        assert_eq!(limits.api_call_limit, 0);
    }

    // ------------------------------------------------------------------
    // Fix E — quota gate must depend on the event type.
    // ------------------------------------------------------------------

    #[test]
    fn quota_limit_for_event_gates_emails_by_email_limit() {
        let limits = PlanLimitRow {
            email_limit: 100,
            api_call_limit: 1_000,
        };

        assert_eq!(
            quota_limit_for_event(MeterEventType::EmailsSent, &limits),
            100
        );
        assert_eq!(
            quota_limit_for_event(MeterEventType::EmailsDelivered, &limits),
            100
        );
    }

    #[test]
    fn quota_limit_for_event_gates_api_calls_by_api_call_limit() {
        let limits = PlanLimitRow {
            email_limit: 100,
            api_call_limit: 1_000,
        };

        // A tiny email limit must NOT block API calls (old behaviour).
        assert_eq!(
            quota_limit_for_event(MeterEventType::ApiCalls, &limits),
            1_000
        );

        let email_tight = PlanLimitRow {
            email_limit: 1,
            api_call_limit: 1_000,
        };
        assert_eq!(
            quota_limit_for_event(MeterEventType::ApiCalls, &email_tight),
            1_000
        );
    }

    #[test]
    fn quota_limit_for_event_leaves_unmetered_quotas_unlimited() {
        let limits = PlanLimitRow {
            email_limit: 100,
            api_call_limit: 1_000,
        };

        // plans.rs has no per-type fields for these — they are recorded but
        // not quota-gated (-1 = unlimited).
        for event_type in [
            MeterEventType::WebhooksDelivered,
            MeterEventType::DedicatedIpHours,
            MeterEventType::StorageGbHours,
            MeterEventType::BandwidthGb,
        ] {
            assert_eq!(
                quota_limit_for_event(event_type, &limits),
                -1,
                "{event_type:?} must not be gated by the email limit"
            );
        }
    }

    // ------------------------------------------------------------------
    // Fix I15 — explicit timezone support for usage periods.
    // ------------------------------------------------------------------

    #[test]
    fn month_period_defaults_to_utc_month_boundaries() {
        let now = DateTime::parse_from_rfc3339("2026-04-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let (start, end) = month_period_for_tz(now, None).expect("utc period");

        assert_eq!(start.to_rfc3339(), "2026-04-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-05-01T00:00:00+00:00");
    }

    #[test]
    fn month_period_respects_explicit_tallinn_timezone() {
        // 2026-03-31T23:30:00Z is already April 1st in Tallinn (UTC+3).
        let now = DateTime::parse_from_rfc3339("2026-03-31T23:30:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let (start, end) = month_period_for_tz(now, Some("Europe/Tallinn")).expect("period");

        // April in Tallinn starts at 2026-03-31T21:00:00Z (EEST, UTC+3).
        assert_eq!(start.to_rfc3339(), "2026-03-31T21:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-04-30T21:00:00+00:00");
    }

    #[test]
    fn month_period_rejects_unknown_timezone() {
        let now = Utc::now();
        assert!(month_period_for_tz(now, Some("Mars/Olympus")).is_err());
    }

    #[test]
    fn tenant_plan_limits_sql_resolves_plan_overrides() {
        // Fix I2 — the shared limit SQL must consult plan_overrides before
        // the tenant's own plan.
        assert!(TENANT_PLAN_LIMITS_SQL.contains("plan_overrides"));
        assert!(TENANT_PLAN_LIMITS_SQL.contains("COALESCE(po.plan, t.plan)"));
        assert!(TENANT_PLAN_LIMITS_SQL.contains("po.active = true"));
    }

    #[test]
    fn event_type_roundtrip() {
        for et in [
            MeterEventType::EmailsSent,
            MeterEventType::EmailsDelivered,
            MeterEventType::ApiCalls,
            MeterEventType::WebhooksDelivered,
            MeterEventType::DedicatedIpHours,
            MeterEventType::StorageGbHours,
            MeterEventType::BandwidthGb,
        ] {
            let s = event_type_to_str(et);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn usage_counter_key_anchor_follows_the_cycle_not_the_calendar_month() {
        let anchor = chrono::NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let at = DateTime::parse_from_rfc3339("2026-04-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // Cycle-day itself: new cycle, new key.
        assert_eq!(
            usage_counter_key_anchored("t", MeterEventType::EmailsSent, at, Some(anchor)),
            "meter:rt:t:emails_sent:c2026-04"
        );
        // Day before the cycle rolls over: still the March cycle.
        let before = DateTime::parse_from_rfc3339("2026-04-14T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            usage_counter_key_anchored("t", MeterEventType::EmailsSent, before, Some(anchor)),
            "meter:rt:t:emails_sent:c2026-03"
        );
        // A 31st anchor clamps in short months: the January cycle runs
        // Jan 31 .. Feb 27 and the February cycle begins on the clamped
        // Feb 28 — one boundary per month, never a skipped or doubled
        // cycle. (Stripe refreshes billing_cycle_start/end every cycle via
        // webhook, so the anchor's day self-corrects each period.)
        let anchor31 = chrono::NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
        let jan_cycle_still = DateTime::parse_from_rfc3339("2026-02-27T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            usage_counter_key_anchored(
                "t",
                MeterEventType::EmailsSent,
                jan_cycle_still,
                Some(anchor31)
            ),
            "meter:rt:t:emails_sent:c2026-01"
        );
        let feb_cycle_start = DateTime::parse_from_rfc3339("2026-02-28T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            usage_counter_key_anchored(
                "t",
                MeterEventType::EmailsSent,
                feb_cycle_start,
                Some(anchor31)
            ),
            "meter:rt:t:emails_sent:c2026-02"
        );
        // No anchor: the legacy UTC calendar key.
        assert_eq!(
            usage_counter_key_anchored("t", MeterEventType::EmailsSent, at, None),
            "meter:rt:t:emails_sent:2026-04"
        );
    }

    #[test]
    fn usage_counter_key_uses_billing_period() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-04-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            usage_counter_key("tenant_123", MeterEventType::EmailsSent, at),
            "meter:rt:tenant_123:emails_sent:2026-04"
        );
    }

    /// Fix F3 — the Redis-outage fallback window must be the same period the
    /// enforced counter labels: the anchored cycle START, not the calendar
    /// month, and it must agree with the `c{Y}-{M}` label of the key.
    #[test]
    fn most_recent_anchored_cycle_start_matches_key_label() {
        let anchor = chrono::NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let at = chrono::DateTime::parse_from_rfc3339("2026-04-14T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let (year, month, start) = most_recent_anchored_cycle(at, anchor);
        assert_eq!((year, month), (2026, 3));
        assert_eq!(start.to_rfc3339(), "2026-03-15T00:00:00+00:00");

        // Cycle-day boundary: exactly at the cycle start is the new cycle.
        let (year, month, start) = most_recent_anchored_cycle(
            chrono::DateTime::parse_from_rfc3339("2026-04-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            anchor,
        );
        assert_eq!((year, month), (2026, 4));
        assert_eq!(start.to_rfc3339(), "2026-04-15T00:00:00+00:00");
    }

    #[test]
    fn normalize_usage_metadata_preserves_object_payloads() {
        let normalized = normalize_usage_metadata(Some(serde_json::json!({ "source": "api" })));

        assert_eq!(normalized.get("source"), Some(&serde_json::json!("api")));
    }

    #[test]
    fn normalize_usage_metadata_wraps_scalar_payloads() {
        let normalized = normalize_usage_metadata(Some(serde_json::json!("email-123")));

        assert_eq!(
            normalized.get("value"),
            Some(&serde_json::json!("email-123"))
        );
    }

    #[test]
    fn build_metering_audit_metadata_preserves_event_context() {
        let recorded_at = chrono::DateTime::parse_from_rfc3339("2026-04-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let metadata = serde_json::json!({ "source": "api" });

        let audit_metadata =
            build_metering_audit_metadata("emails_sent", 42, recorded_at, &metadata);

        assert_eq!(
            audit_metadata.get("eventType"),
            Some(&serde_json::json!("emails_sent"))
        );
        assert_eq!(audit_metadata.get("quantity"), Some(&serde_json::json!(42)));
        assert_eq!(
            audit_metadata.get("recordedAt"),
            Some(&serde_json::json!("2026-04-15T12:30:00+00:00"))
        );
        assert_eq!(audit_metadata.get("metadata"), Some(&metadata));
    }

    #[test]
    fn attach_subscription_context_adds_subscription_fields() {
        let context = MeteringSubscriptionContext {
            subscription_id: "sub_123".into(),
            period_start: chrono::DateTime::parse_from_rfc3339("2026-04-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            period_end: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        let enriched = attach_subscription_context(serde_json::Map::new(), Some(&context));

        assert_eq!(enriched["subscriptionId"], serde_json::json!("sub_123"));
        assert_eq!(
            enriched["subscriptionPeriodStart"],
            serde_json::json!("2026-04-01T00:00:00+00:00")
        );
        assert_eq!(
            enriched["subscriptionPeriodEnd"],
            serde_json::json!("2026-05-01T00:00:00+00:00")
        );
    }

    #[test]
    fn attach_subscription_context_keeps_existing_subscription_id() {
        let context = MeteringSubscriptionContext {
            subscription_id: "sub_new".into(),
            period_start: chrono::DateTime::parse_from_rfc3339("2026-04-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            period_end: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let mut metadata = serde_json::Map::new();
        metadata.insert("subscriptionId".into(), serde_json::json!("sub_existing"));

        let enriched = attach_subscription_context(metadata, Some(&context));

        assert_eq!(
            enriched["subscriptionId"],
            serde_json::json!("sub_existing")
        );
    }

    // ------------------------------------------------------------------
    // Audit F71 — the logical usage operation is bound to its content.
    // ------------------------------------------------------------------

    #[test]
    fn usage_payload_hash_is_deterministic_for_identical_content() {
        let id = Uuid::new_v4();
        let metadata = serde_json::json!({ "messageId": "m-1" });
        let first = usage_payload_hash("tenant-1", "emails_sent", 3, id, Some(&metadata));
        let second = usage_payload_hash("tenant-1", "emails_sent", 3, id, Some(&metadata));
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn usage_payload_hash_rejects_divergent_reuse() {
        let id = Uuid::new_v4();
        let base = usage_payload_hash("tenant-1", "emails_sent", 3, id, None);
        // Different tenant, kind, quantity, event id or payload content
        // each produce a DIFFERENT hash — the ledger flags them as a
        // rejected Conflict, never as a replay.
        assert_ne!(
            usage_payload_hash("tenant-2", "emails_sent", 3, id, None),
            base
        );
        assert_ne!(
            usage_payload_hash("tenant-1", "api_calls", 3, id, None),
            base
        );
        assert_ne!(
            usage_payload_hash("tenant-1", "emails_sent", 4, id, None),
            base
        );
        assert_ne!(
            usage_payload_hash("tenant-1", "emails_sent", 3, Uuid::new_v4(), None),
            base
        );
        assert_ne!(
            usage_payload_hash(
                "tenant-1",
                "emails_sent",
                3,
                id,
                Some(&serde_json::json!({ "messageId": "m-2" }))
            ),
            base
        );
        // Absent and explicitly-null metadata bind identically.
        assert_eq!(
            usage_payload_hash(
                "tenant-1",
                "emails_sent",
                3,
                id,
                Some(&serde_json::Value::Null)
            ),
            base
        );
    }

    #[test]
    fn usage_operation_key_is_globally_unique_per_logical_operation() {
        let id = Uuid::new_v4();
        assert_eq!(
            usage_operation_key("tenant-1", "emails_sent", id),
            format!("tenant-1:emails_sent:{id}")
        );
        // Different tenant or kind with the SAME event id is a DIFFERENT
        // logical operation — but the ledger still binds the tenant/kind
        // through the payload hash.
        assert_ne!(
            usage_operation_key("tenant-2", "emails_sent", id),
            usage_operation_key("tenant-1", "emails_sent", id)
        );
        assert_ne!(
            usage_operation_key("tenant-1", "api_calls", id),
            usage_operation_key("tenant-1", "emails_sent", id)
        );
    }
}
