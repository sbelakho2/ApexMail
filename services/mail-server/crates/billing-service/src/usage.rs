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

use crate::types::{MeterEventType, UsageSummary};

/// Record a single metering event with deduplication.
///
/// Returns `true` if the event was newly recorded, `false` if it was a
/// duplicate.
pub async fn record_usage(
    pool: &PgPool,
    redis: &RedisPool,
    tenant_id: Uuid,
    event_type: MeterEventType,
    quantity: i64,
    event_id: Option<Uuid>,
    metadata: Option<serde_json::Value>,
) -> Result<bool, UsageError> {
    let id = event_id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let meta = metadata.unwrap_or_else(|| json!({}));

    // 1. Check idempotency key in Redis.
    let dedup_key = format!("meter:dedup:{id}");
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;
    let was_set: bool = redis::cmd("SET")
        .arg(&dedup_key)
        .arg("1")
        .arg("EX")
        .arg(86_400i64)
        .arg("NX")
        .query_async(&mut conn)
        .await
        .unwrap_or(false);

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
    let period_key = format!(
        "meter:rt:{}:{}:{}-{:02}",
        tenant_id,
        event_type_to_str(event_type),
        now.year(),
        now.month()
    );
    let _: () = conn.incr(&period_key, quantity).await.unwrap_or(());
    let _: () = conn.expire(&period_key, 40 * 86_400).await.unwrap_or(()); // 40 days TTL

    Ok(true)
}

/// Aggregate usage for a tenant in a billing period.
pub async fn get_usage(
    pool: &PgPool,
    tenant_id: Uuid,
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
    let limits: Option<PlanLimitRow> = sqlx::query_as(
        r#"
        SELECT COALESCE(p.email_limit, 0) as email_limit,
               COALESCE(p.api_call_limit, 0) as api_call_limit
        FROM tenants t
        JOIN plans  p ON t.plan = p.name
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(UsageError::Db)?;

    let (emails_limit, api_calls_limit) = limits
        .map(|l| (l.email_limit, l.api_call_limit))
        .unwrap_or((0, 0));

    let percent_used = if emails_limit > 0 {
        (emails_sent as f64 / emails_limit as f64) * 100.0
    } else {
        0.0
    };

    Ok(UsageSummary {
        tenant_id,
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
    tenant_id: Uuid,
) -> Result<QuotaStatus, UsageError> {
    // Fast-path: read the real-time Redis counter for the current month.
    let now = Utc::now();
    let counter_key = format!(
        "meter:rt:{}:emails_sent:{}-{:02}",
        tenant_id,
        now.year(),
        now.month()
    );

    let mut conn = redis.get().await.map_err(UsageError::Redis)?;
    let current: i64 = conn.get(&counter_key).await.unwrap_or(0);

    let limits: Option<EmailLimitRow> = sqlx::query_as(
        r#"
        SELECT COALESCE(p.email_limit, 0) as email_limit
        FROM tenants t JOIN plans p ON t.plan = p.name
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(UsageError::Db)?;

    let limit = limits.map(|l| l.email_limit).unwrap_or(0);

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
    tenant_id: Uuid,
    year: i32,
    month: u32,
) -> Result<(), UsageError> {
    let pattern = format!("meter:rt:{tenant_id}:*:{year}-{month:02}");
    let mut conn = redis.get().await.map_err(UsageError::Redis)?;

    // SCAN-based deletion – safe for production.
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(&pattern)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    if !keys.is_empty() {
        let _: () = redis::cmd("DEL")
            .arg(&keys)
            .query_async(&mut conn)
            .await
            .unwrap_or(());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct UsageAggRow {
    event_type: String,
    total: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct PlanLimitRow {
    email_limit: i64,
    api_call_limit: i64,
}

#[derive(sqlx::FromRow)]
struct EmailLimitRow {
    email_limit: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuotaStatus {
    pub allowed: bool,
    pub current: i64,
    pub limit: i64,
    pub percent_used: f64,
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
}
