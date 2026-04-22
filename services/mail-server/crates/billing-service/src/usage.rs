//! Usage tracking and metering service.
//!
//! Records metering events with idempotency via Redis dedup keys, aggregates
//! usage per billing period, and checks quotas.

use chrono::{DateTime, Datelike, Utc};
use deadpool_redis::Pool as RedisPool;
use redis::AsyncCommands;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::plans::builtin_quota_limits;
use crate::types::{MeterEventType, UsageSummary};

/// Record a single metering event with deduplication.
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
    let id = event_id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let meta = metadata.unwrap_or_else(|| json!({}));

// 1. Check idempotency key in Redis.
    let dedup_key = usage_dedup_key(id);
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;
    let was_set: bool = redis::cmd("SET")
        .arg(&dedup_key)
        .arg("1")
        .arg("EX")
        .arg(86_400i64)
        .arg("NX")
        .query_async(&mut conn)
        .await
        .map_err(UsageError::RedisCmd)?;

    if !was_set {
        return Ok(false); // duplicate
    }

// 2. Persist to DB.
    sqlx::query(
        r#"
        INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
        VALUES ($1, $2, $3::text::meter_event_type, $4, $5, $6)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(event_type_to_str(event_type))
    .bind(quantity)
    .bind(now)
    .bind(&meta)
    .execute(pool)
    .await
    .map_err(UsageError::Db)?;

// 3. Bump real-time Redis counter.
    let period_key = usage_counter_key(tenant_id, event_type, now);
    let _: i64 = conn.incr(&period_key, quantity).await.map_err(UsageError::RedisCmd)?;
    let _: () = conn.expire(&period_key, 40 * 86_400).await.map_err(UsageError::RedisCmd)?; // 40 days TTL

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

// Look up plan limits.
    let limits: Option<TenantPlanLimitRow> = sqlx::query_as(
        r#"
        SELECT t.plan as plan_name,
               p.email_limit,
               p.api_call_limit
        FROM tenants t
        LEFT JOIN plans p ON t.plan = p.name
        WHERE t.id = $1
        "#,
    )
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
// Fast-path:read the real-time Redis counter for the current month.
    let now = Utc::now();
    let counter_key = usage_counter_key(tenant_id, MeterEventType::EmailsSent, now);

// that metering is degraded rather than completely broken.
    let current = match redis.get().await {
        Ok(mut conn) => {
            let val: Option<i64> = conn.get(&counter_key).await.map_err(UsageError::RedisCmd)?;
            val.unwrap_or(0)
        }
        Err(e) => {
            tracing::warn!(error = %e, tenant_id, "Redis unavailable for quota check — falling back to DB aggregate");
            let period_start = Utc::now()
                .date_naive()
                .with_day(1)
                .unwrap_or(Utc::now().date_naive());
            let period_start = period_start.and_hms_opt(0, 0, 0)
                .unwrap_or_default();
            let period_start = DateTime::<Utc>::from_naive_utc_and_offset(period_start, Utc);

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

    let limits: Option<TenantPlanLimitRow> = sqlx::query_as(
        r#"
        SELECT t.plan as plan_name,
               p.email_limit,
               p.api_call_limit
        FROM tenants t
        LEFT JOIN plans p ON t.plan = p.name
        WHERE t.id = $1
        "#,
    )
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
pub async fn reset_monthly_counters(
    redis: &RedisPool,
    tenant_id: &str,
    year: i32,
    month: u32,
) -> Result<(), UsageError> {
    let pattern = format!("meter:rt:{tenant_id}:*:{year}-{month:02}");
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;

// Use SCAN instead of KEYS for production safety — KEYS blocks Redis.
    let mut cursor: u64 = 0;
    let mut all_keys: Vec<String> = Vec::new();
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
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

    if !all_keys.is_empty() {
        let _: () = redis::cmd("DEL")
            .arg(&all_keys)
            .query_async(&mut conn)
            .await
            .map_err(UsageError::RedisCmd)?;
    }

    Ok(())
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
    let id = event_id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let meta = metadata.unwrap_or_else(|| json!({}));

// 1. Dedup check (same as record_usage).
    let dedup_key = usage_dedup_key(id);
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;
    let was_set: bool = redis::cmd("SET")
        .arg(&dedup_key)
        .arg("1")
        .arg("EX")
        .arg(86_400i64)
        .arg("NX")
        .query_async(&mut conn)
        .await
        .map_err(UsageError::RedisCmd)?;

    if !was_set {
// Already processed — read current counter for informational purposes.
        let counter_key = usage_counter_key(tenant_id, event_type, now);
        let current: i64 = conn.get(&counter_key).await.unwrap_or(0);
        return Ok(QuotaRecordResult {
            allowed: true,
            current,
            duplicate: true,
        });
    }

// 2. Fetch plan limit from Postgres.
    let limit_row: Option<TenantPlanLimitRow> = sqlx::query_as(
        r#"
        SELECT t.plan as plan_name,
               p.email_limit,
               p.api_call_limit
        FROM tenants t
        LEFT JOIN plans p ON t.plan = p.name
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(UsageError::Db)?;

    let limit = resolve_plan_limits(limit_row).email_limit;

// 3. Atomic check-and-increment via Lua.
    let counter_key = usage_counter_key(tenant_id, event_type, now);
    let ttl_seconds: i64 = 40 * 86_400; // 40 days

    let new_val: i64 = redis::Script::new(QUOTA_CHECK_AND_INCR_LUA)
        .key(&counter_key)
        .arg(limit)
        .arg(quantity)
        .arg(ttl_seconds)
        .invoke_async(&mut conn)
        .await
        .map_err(UsageError::RedisCmd)?;

    if new_val < 0 {
// Quota exceeded — roll back the dedup key so a retry after a plan
// upgrade can succeed.
        let _: () = conn.del(&dedup_key).await.unwrap_or(());
        return Ok(QuotaRecordResult {
            allowed: false,
            current: new_val,
            duplicate: false,
        });
    }

// 4. Persist to DB.
    if let Err(db_error) = sqlx::query(
        r#"
        INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
        VALUES ($1, $2, $3::text::meter_event_type, $4, $5, $6)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(event_type_to_str(event_type))
    .bind(quantity)
    .bind(now)
    .bind(&meta)
    .execute(pool)
    .await
    {
        if let Err(rollback_error) = rollback_quota_reservation(
            redis,
            tenant_id,
            event_type,
            quantity,
            id,
            now,
        )
        .await
        {
            tracing::error!(
                error = %rollback_error,
                tenant_id,
                event_id = %id,
                "failed to roll back quota reservation after metering DB insert failure"
            );
        }

        return Err(UsageError::Db(db_error));
    }

    Ok(QuotaRecordResult {
        allowed: true,
        current: new_val,
        duplicate: false,
    })
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
    sqlx::query("DELETE FROM metering_events WHERE id = $1")
        .bind(event_id)
        .execute(pool)
        .await
        .map_err(UsageError::Db)?;

    rollback_quota_reservation(
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
}

fn resolve_plan_limits(row: Option<TenantPlanLimitRow>) -> PlanLimitRow {
    match row {
        Some(row) => {
            let (fallback_email_limit, fallback_api_call_limit) =
                builtin_quota_limits(Some(&row.plan_name));

            PlanLimitRow {
                email_limit: row.email_limit.unwrap_or(fallback_email_limit),
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

fn usage_counter_key(tenant_id: &str, event_type: MeterEventType, at: DateTime<Utc>) -> String {
    format!(
        "meter:rt:{}:{}:{}-{:02}",
        tenant_id,
        event_type_to_str(event_type),
        at.year(),
        at.month()
    )
}

async fn rollback_quota_reservation(
    redis: &RedisPool,
    tenant_id: &str,
    event_type: MeterEventType,
    quantity: i64,
    event_id: Uuid,
    recorded_at: DateTime<Utc>,
) -> Result<(), UsageError> {
    let counter_key = usage_counter_key(tenant_id, event_type, recorded_at);
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
    #[error("redis pool error: {0}")]
    Redis(#[from] deadpool_redis::PoolError),
    #[error("redis command error: {0}")]
    RedisCmd(#[from] redis::RedisError),
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
        }));

        assert_eq!(limits.email_limit, 250_000);
        assert_eq!(limits.api_call_limit, 3_000_000);
    }

    #[test]
    fn resolve_plan_limits_fall_back_to_builtin_plan_defaults() {
        let limits = resolve_plan_limits(Some(TenantPlanLimitRow {
            plan_name: "free".to_string(),
            email_limit: None,
            api_call_limit: None,
        }));

        assert_eq!(limits.email_limit, 3_000);
        assert_eq!(limits.api_call_limit, 50_000);
    }

    #[test]
    fn resolve_plan_limits_keep_missing_tenants_denied() {
        let limits = resolve_plan_limits(None);

        assert_eq!(limits.email_limit, 0);
        assert_eq!(limits.api_call_limit, 0);
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
    fn usage_counter_key_uses_billing_period() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-04-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            usage_counter_key("tenant_123", MeterEventType::EmailsSent, at),
            "meter:rt:tenant_123:emails_sent:2026-04"
        );
    }
}
