use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Datelike, Timelike, Utc};
use redis::AsyncCommands;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, QueryBuilder};
use tokio::time::{interval_at, Instant, MissedTickBehavior};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::routes::append_audit_log;
use crate::usage::build_metering_audit_metadata;

const HOURLY_TASK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const DEDICATED_IP_TASK_INTERVAL: Duration = Duration::from_secs(30);
const METERING_TASK_INTERVAL: Duration = Duration::from_secs(60);
const USAGE_ALERT_TASK_INTERVAL: Duration = Duration::from_secs(5 * 60);
const COST_MARGIN_TASK_INTERVAL: Duration = Duration::from_secs(15 * 60);
const DAILY_TASK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const WALLET_CLEANUP_INTERVAL: Duration = Duration::from_secs(30 * 60);
const METERING_SCAN_COUNT: usize = 200;
const METERING_RECOVERY_LIMIT: usize = 10_000;
const METERING_PERIOD_TTL_SECONDS: i64 = 40 * 86_400;
const USAGE_ALERT_COOLDOWN_SECONDS: u64 = 60 * 60;
const COST_MARGIN_WARNING_THRESHOLD: f64 = 20.0;
const COST_MARGIN_CRITICAL_THRESHOLD: f64 = 10.0;
const SLA_AVAILABILITY_TARGET: f64 = 99.9;

static DEDICATED_IP_TABLE_MISSING_LOGGED: AtomicBool = AtomicBool::new(false);

pub fn start_periodic_jobs(state: std::sync::Arc<AppState>) {
    let dedicated_ip_state = state.clone();
    tokio::spawn(async move {
        let client = Client::new();

        match process_dedicated_ip_billing(dedicated_ip_state.as_ref(), &client).await {
            Ok(result) if result.charged > 0 || result.canceled > 0 => {
                info!(charged = result.charged, canceled = result.canceled, "processed dedicated IP billing sync on startup");
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to process dedicated IP billing sync on startup");
            }
        }

        let mut interval = interval_at(Instant::now() + DEDICATED_IP_TASK_INTERVAL, DEDICATED_IP_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_dedicated_ip_billing(dedicated_ip_state.as_ref(), &client).await {
                Ok(result) if result.charged > 0 || result.canceled > 0 => {
                    info!(charged = result.charged, canceled = result.canceled, "processed dedicated IP billing sync");
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process dedicated IP billing sync");
                }
            }
        }
    });

    let metering_state = state.clone();
    tokio::spawn(async move {
        match drain_pending_metering_events(metering_state.as_ref(), METERING_RECOVERY_LIMIT).await {
            Ok(result) if result.processed_count > 0 || result.discarded_count > 0 => {
                info!(
                    processed_count = result.processed_count,
                    discarded_count = result.discarded_count,
                    "recovered pending metering events on startup"
                );
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to recover pending metering events on startup");
            }
        }

        let mut interval = interval_at(Instant::now() + METERING_TASK_INTERVAL, METERING_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match drain_pending_metering_events(metering_state.as_ref(), METERING_RECOVERY_LIMIT).await {
                Ok(result) if result.processed_count > 0 || result.discarded_count > 0 => {
                    info!(
                        processed_count = result.processed_count,
                        discarded_count = result.discarded_count,
                        "drained pending metering events"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to drain pending metering events");
                }
            }
        }
    });

    let wallet_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(Instant::now() + WALLET_CLEANUP_INTERVAL, WALLET_CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_expired_wallet_reservations(wallet_state.as_ref()).await {
                Ok(released_count) if released_count > 0 => {
                    info!(released_count, "released expired wallet reservations");
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to release expired wallet reservations");
                }
            }
        }
    });

    let usage_alert_state = state.clone();
    tokio::spawn(async move {
        let client = Client::new();
        let mut interval = interval_at(Instant::now() + USAGE_ALERT_TASK_INTERVAL, USAGE_ALERT_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_usage_alerts(usage_alert_state.as_ref(), &client).await {
                Ok(result) if result.tenants_checked > 0 || result.alerts_triggered > 0 => {
                    info!(
                        tenants_checked = result.tenants_checked,
                        alerts_triggered = result.alerts_triggered,
                        "processed usage alerts"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process usage alerts");
                }
            }
        }
    });

    let cost_margin_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(Instant::now() + COST_MARGIN_TASK_INTERVAL, COST_MARGIN_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_cost_margin_checks(cost_margin_state.as_ref()).await {
                Ok(result) if result.checked > 0 || result.warnings > 0 || result.critical > 0 => {
                    info!(
                        checked = result.checked,
                        warnings = result.warnings,
                        critical = result.critical,
                        "processed tenant cost margin checks"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process tenant cost margin checks");
                }
            }
        }
    });

    let sla_state = state.clone();
    tokio::spawn(async move {
        match process_monthly_sla_credits(sla_state.as_ref()).await {
            Ok(result) if result.tenants_checked > 0 || result.credits_created > 0 => {
                info!(
                    tenants_checked = result.tenants_checked,
                    credits_created = result.credits_created,
                    "processed monthly SLA credits on startup"
                );
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to process monthly SLA credits on startup");
            }
        }

        let next_run = next_day_start(Utc::now());
        let initial_delay = (next_run - Utc::now())
            .to_std()
            .unwrap_or(DAILY_TASK_INTERVAL);
        let mut interval = interval_at(Instant::now() + initial_delay, DAILY_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_monthly_sla_credits(sla_state.as_ref()).await {
                Ok(result) if result.tenants_checked > 0 || result.credits_created > 0 => {
                    info!(
                        tenants_checked = result.tenants_checked,
                        credits_created = result.credits_created,
                        "processed monthly SLA credits"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process monthly SLA credits");
                }
            }
        }
    });

    tokio::spawn(async move {
        let client = Client::new();
        let mut interval = interval_at(Instant::now() + HOURLY_TASK_INTERVAL, HOURLY_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_grace_period_expirations(state.as_ref(), 100).await {
                Ok(result) if result.processed_count > 0 || result.purged_messages_count > 0 => {
                    info!(
                        processed_count = result.processed_count,
                        purged_messages_count = result.purged_messages_count,
                        "processed expired dunning grace periods"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process dunning grace periods");
                }
            }

            match process_scheduled_retries(state.as_ref(), &client).await {
                Ok(result) if result.attempted > 0 => {
                    info!(attempted = result.attempted, succeeded = result.succeeded, "processed scheduled Stripe retries");
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process scheduled Stripe retries");
                }
            }

            match cleanup_stuck_subscription_sagas(state.as_ref()).await {
                Ok(cleaned) if cleaned > 0 => {
                    info!(cleaned, "cleaned stuck subscription sagas");
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to clean stuck subscription sagas");
                }
            }
        }
    });
}

#[derive(Debug)]
struct GracePeriodResult {
    processed_count: i64,
    purged_messages_count: i64,
}

#[derive(Debug)]
struct RetryResult {
    attempted: i64,
    succeeded: i64,
}

#[derive(Debug)]
struct MeteringDrainResult {
    processed_count: i64,
    discarded_count: i64,
}

#[derive(Debug)]
struct UsageAlertSweepResult {
    tenants_checked: i64,
    alerts_triggered: i64,
}

#[derive(Debug)]
struct CostMarginSweepResult {
    checked: i64,
    warnings: i64,
    critical: i64,
}

#[derive(Debug)]
struct SlaCreditSweepResult {
    tenants_checked: i64,
    credits_created: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingMeterEvent {
    id: String,
    tenant_id: String,
    event_type: String,
    quantity: i64,
    timestamp: DateTime<Utc>,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Clone)]
struct PreparedMeterEvent {
    raw_id: String,
    normalized_id: Uuid,
    tenant_id: String,
    event_type: String,
    quantity: i64,
    timestamp: DateTime<Utc>,
    metadata: Value,
}

#[derive(Debug, FromRow)]
struct UsageAlertConfigRow {
    id: Uuid,
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
}

#[derive(Debug, FromRow)]
struct TenantAlertSettingsRow {
    settings: Value,
}

#[derive(Debug, FromRow)]
struct TenantCostSummaryRow {
    storage_cost: i64,
    bandwidth_cost: i64,
    compute_cost: i64,
    dedicated_ip_cost: i64,
    total_cost: i64,
    revenue: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CostMarginStatus {
    Healthy,
    Warning,
    Critical,
}

impl CostMarginStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, FromRow)]
struct SlaMetricCandidateRow {
    tenant_id: String,
    uptime_percent: f64,
    features: Value,
}

#[derive(Debug)]
struct DedicatedIpSyncResult {
    charged: i64,
    canceled: i64,
}

#[derive(Debug, FromRow)]
struct DedicatedIpPendingRow {
    id: String,
    tenant_id: String,
    ip_address: String,
    stripe_subscription_item_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct TenantStripeSubscriptionRow {
    stripe_subscription_id: String,
}

#[derive(Debug, Deserialize)]
struct StripeSubscriptionItemResponse {
    id: String,
}

#[derive(Debug, FromRow)]
struct ExpiredTenantPurgeRow {
    tenant_id: String,
    purged_count: i32,
}

async fn process_grace_period_expirations(
    state: &AppState,
    batch_size: i64,
) -> Result<GracePeriodResult, String> {
    let mut total_processed = 0_i64;
    let mut total_purged = 0_i64;
    let now = Utc::now();

    loop {
        let rows = sqlx::query_as::<_, ExpiredTenantPurgeRow>(
            r#"
            WITH expired_tenants AS (
                SELECT tenant_id FROM dunning_records
                WHERE status = 'hard_suspended'
                  AND grace_period_ends_at IS NOT NULL
                  AND grace_period_ends_at < $1
                ORDER BY grace_period_ends_at ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            ),
            purge_messages AS (
                DELETE FROM messages
                WHERE tenant_id IN (SELECT tenant_id FROM expired_tenants)
                  AND status = 'dunning_queued'
                RETURNING tenant_id
            ),
            purge_counts AS (
                SELECT tenant_id, COUNT(*) AS purged_count
                FROM purge_messages
                GROUP BY tenant_id
            ),
            queue_notifications AS (
                INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
                SELECT gen_random_uuid(), et.tenant_id, 'messages_purged',
                       jsonb_build_object('purgedCount', COALESCE(pc.purged_count, 0)),
                       'pending', NOW()
                FROM expired_tenants et
                LEFT JOIN purge_counts pc ON et.tenant_id = pc.tenant_id
                RETURNING tenant_id
            ),
            update_dunning AS (
                UPDATE dunning_records
                SET grace_period_ends_at = NULL, updated_at = NOW()
                WHERE tenant_id IN (SELECT tenant_id FROM expired_tenants)
                RETURNING tenant_id
            )
            SELECT et.tenant_id, COALESCE(pc.purged_count, 0)::int AS purged_count
            FROM expired_tenants et
            LEFT JOIN purge_counts pc ON et.tenant_id = pc.tenant_id
            "#,
        )
        .bind(now)
        .bind(batch_size)
        .fetch_all(&state.db)
        .await
        .map_err(|error| format!("Failed to process grace-period expirations: {error}"))?;

        let batch_count = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        if batch_count == 0 {
            break;
        }

        let batch_purged: i64 = rows
            .iter()
            .map(|row| i64::from(row.purged_count))
            .sum();

        total_processed += batch_count;
        total_purged += batch_purged;

        for row in &rows {
            info!(tenant_id = %row.tenant_id, purged_count = row.purged_count, "purged dunning queued messages after grace period");
        }

        if batch_count < batch_size {
            break;
        }
    }

    Ok(GracePeriodResult {
        processed_count: total_processed,
        purged_messages_count: total_purged,
    })
}

async fn drain_pending_metering_events(
    state: &AppState,
    limit: usize,
) -> Result<MeteringDrainResult, String> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|error| format!("Failed to get Redis connection for metering recovery: {error}"))?;

    let pending_keys = scan_metering_pending_keys(&mut conn, limit).await?;
    if pending_keys.is_empty() {
        return Ok(MeteringDrainResult {
            processed_count: 0,
            discarded_count: 0,
        });
    }

    let payloads: Vec<Option<String>> = redis::cmd("MGET")
        .arg(&pending_keys)
        .query_async(&mut conn)
        .await
        .map_err(|error| format!("Failed to load pending metering events from Redis: {error}"))?;

    let mut valid_events = Vec::new();
    let mut cleanup_keys = Vec::new();

    for (key, payload) in pending_keys.iter().zip(payloads.into_iter()) {
        let Some(payload) = payload else {
            cleanup_keys.push(key.clone());
            continue;
        };

        match serde_json::from_str::<PendingMeterEvent>(&payload) {
            Ok(event) => valid_events.push(PreparedMeterEvent {
                raw_id: event.id.clone(),
                normalized_id: normalize_metering_event_id(&event.id),
                tenant_id: event.tenant_id,
                event_type: event.event_type,
                quantity: event.quantity,
                timestamp: event.timestamp,
                metadata: event.metadata,
            }),
            Err(error) => {
                warn!(key = %key, error = %error, "discarding malformed pending metering event");
                cleanup_keys.push(key.clone());
            }
        }
    }

    if valid_events.is_empty() {
        delete_redis_keys(&mut conn, &cleanup_keys)
            .await
            .map_err(|error| format!("Failed to clean malformed pending metering events: {error}"))?;

        return Ok(MeteringDrainResult {
            processed_count: 0,
            discarded_count: i64::try_from(cleanup_keys.len()).unwrap_or(i64::MAX),
        });
    }

    let inserted_ids = insert_metering_events(state, &valid_events).await?;
    let inserted_id_set: HashSet<Uuid> = inserted_ids.into_iter().collect();

    let mut pipeline = redis::pipe();
    for key in &cleanup_keys {
        pipeline.del(key).ignore();
    }
    for event in &valid_events {
        pipeline.del(format!("meter:pending:{}", event.raw_id)).ignore();
        if inserted_id_set.contains(&event.normalized_id) {
            let counter_key = metering_counter_key(&event.tenant_id, &event.event_type, event.timestamp);
            pipeline.incr(&counter_key, event.quantity).ignore();
            pipeline.expire(&counter_key, METERING_PERIOD_TTL_SECONDS).ignore();
        }
    }
    let _: () = pipeline
        .query_async(&mut conn)
        .await
        .map_err(|error| format!("Failed to finalize metering recovery in Redis: {error}"))?;

    Ok(MeteringDrainResult {
        processed_count: i64::try_from(inserted_id_set.len()).unwrap_or(i64::MAX),
        discarded_count: i64::try_from(cleanup_keys.len()).unwrap_or(i64::MAX),
    })
}

async fn scan_metering_pending_keys(
    conn: &mut deadpool_redis::Connection,
    limit: usize,
) -> Result<Vec<String>, String> {
    let mut cursor = 0_u64;
    let mut keys = Vec::new();

    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("meter:pending:*")
            .arg("COUNT")
            .arg(METERING_SCAN_COUNT)
            .query_async(conn)
            .await
            .map_err(|error| format!("Failed to scan pending metering keys: {error}"))?;

        keys.extend(batch);
        if keys.len() >= limit {
            keys.truncate(limit);
            return Ok(keys);
        }

        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    Ok(keys)
}

async fn delete_redis_keys(
    conn: &mut deadpool_redis::Connection,
    keys: &[String],
) -> Result<(), redis::RedisError> {
    if keys.is_empty() {
        return Ok(());
    }

    let mut pipeline = redis::pipe();
    for key in keys {
        pipeline.del(key).ignore();
    }
    pipeline.query_async(conn).await
}

async fn insert_metering_events(
    state: &AppState,
    events: &[PreparedMeterEvent],
) -> Result<Vec<Uuid>, String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to start metering recovery transaction: {error}"))?;
    let mut query_builder = QueryBuilder::<Postgres>::new(
        r#"
        INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
        "#,
    );

    query_builder.push_values(events, |mut builder, event| {
        builder
            .push_bind(event.normalized_id)
            .push_bind(&event.tenant_id)
            .push_bind(&event.event_type)
            .push("::text::meter_event_type")
            .push_bind(event.quantity)
            .push_bind(event.timestamp)
            .push_bind(&event.metadata);
    });

    query_builder
        .push(
            r#"
            ON CONFLICT (id) DO NOTHING
            RETURNING id
            "#,
        );

    let inserted_ids = query_builder
        .build_query_scalar::<Uuid>()
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| format!("Failed to persist pending metering events: {error}"))?;

    let inserted_set: HashSet<Uuid> = inserted_ids.iter().copied().collect();
    for event in events.iter().filter(|event| inserted_set.contains(&event.normalized_id)) {
        let mut audit_metadata = build_metering_audit_metadata(
            &event.event_type,
            event.quantity,
            event.timestamp,
            &event.metadata,
        );
        audit_metadata.insert("recovered".into(), json!(true));
        audit_metadata.insert("rawEventId".into(), json!(&event.raw_id));

        append_audit_log(
            &mut tx,
            &event.tenant_id,
            "billing.metering_event_recovered",
            "metering_event",
            Some(&event.normalized_id.to_string()),
            Value::Object(audit_metadata),
            Utc::now(),
        )
        .await
        .map_err(|error| format!("Failed to audit recovered metering event: {error}"))?;
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit metering recovery transaction: {error}"))?;

    Ok(inserted_ids)
}

fn normalize_metering_event_id(raw_id: &str) -> Uuid {
    if let Ok(id) = Uuid::parse_str(raw_id) {
        return id;
    }

    if let Some((_, suffix)) = raw_id.rsplit_once('_') {
        if let Ok(id) = Uuid::parse_str(suffix) {
            return id;
        }
    }

    let digest = Sha256::digest(raw_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn metering_counter_key(tenant_id: &str, event_type: &str, timestamp: DateTime<Utc>) -> String {
    format!(
        "meter:rt:{tenant_id}:{event_type}:{:04}-{:02}",
        timestamp.year(),
        timestamp.month()
    )
}

#[derive(Debug, FromRow)]
struct RetryCandidateRow {
    tenant_id: String,
    stripe_subscription_id: String,
    stripe_customer_id: String,
}

async fn process_scheduled_retries(
    state: &AppState,
    client: &Client,
) -> Result<RetryResult, String> {
    let rows = sqlx::query_as::<_, RetryCandidateRow>(
        r#"
        SELECT d.tenant_id, s.stripe_subscription_id, s.stripe_customer_id
        FROM dunning_records d
        JOIN stripe_subscriptions s ON s.tenant_id = d.tenant_id
        WHERE d.next_retry_at IS NOT NULL
          AND d.next_retry_at <= NOW()
          AND d.status IN ('warning', 'soft_suspended')
          AND s.status IN ('past_due', 'unpaid')
        ORDER BY d.next_retry_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load scheduled Stripe retries: {error}"))?;

    let mut attempted = 0_i64;
    let mut succeeded = 0_i64;

    for row in rows {
        attempted += 1;

        let retry_result: Result<(), String> = async {
            let invoices = stripe_get_json::<StripeInvoiceListResponse>(
                client,
                "/v1/invoices",
                &[
                    ("customer", row.stripe_customer_id.clone()),
                    ("subscription", row.stripe_subscription_id.clone()),
                    ("status", "open".to_string()),
                    ("limit", "1".to_string()),
                ],
            )
            .await?;

            let Some(invoice) = invoices.data.first() else {
                sqlx::query(
                    r#"
                    UPDATE dunning_records
                    SET next_retry_at = NULL, updated_at = NOW()
                    WHERE tenant_id = $1
                    "#,
                )
                .bind(&row.tenant_id)
                .execute(&state.db)
                .await
                .map_err(|error| format!("Failed to clear next_retry_at for {}: {error}", row.tenant_id))?;
                return Ok(());
            };

            stripe_post_json::<serde_json::Value>(
                client,
                &format!("/v1/invoices/{}/pay", invoice.id),
            )
            .await?;

            mark_payment_recovered(state, &row.tenant_id).await?;
            Ok(())
        }
        .await;

        match retry_result {
            Ok(()) => {
                succeeded += 1;
            }
            Err(error_message) => {
                warn!(tenant_id = %row.tenant_id, error = %error_message, "scheduled Stripe retry failed");
                if let Err(error) = sqlx::query(
                    r#"
                    UPDATE dunning_records
                    SET next_retry_at = NOW() + INTERVAL '1 day', updated_at = NOW()
                    WHERE tenant_id = $1
                    "#,
                )
                .bind(&row.tenant_id)
                .execute(&state.db)
                .await
                {
                    error!(tenant_id = %row.tenant_id, error = %error, "failed to reschedule dunning retry after Stripe retry failure");
                }
            }
        }
    }

    Ok(RetryResult { attempted, succeeded })
}

async fn process_usage_alerts(
    state: &AppState,
    client: &Client,
) -> Result<UsageAlertSweepResult, String> {
    let tenant_ids: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT tenant_id
        FROM usage_alert_configs
        WHERE enabled = true
        ORDER BY tenant_id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load usage alert tenants: {error}"))?;

    let mut alerts_triggered = 0_i64;
    for tenant_id in &tenant_ids {
        match process_usage_alerts_for_tenant(state, client, tenant_id).await {
            Ok(count) => alerts_triggered += count,
            Err(error_message) => {
                warn!(tenant_id = %tenant_id, error = %error_message, "failed to process usage alerts for tenant");
            }
        }
    }

    Ok(UsageAlertSweepResult {
        tenants_checked: i64::try_from(tenant_ids.len()).unwrap_or(i64::MAX),
        alerts_triggered,
    })
}

async fn process_usage_alerts_for_tenant(
    state: &AppState,
    client: &Client,
    tenant_id: &str,
) -> Result<i64, String> {
    let period_start = month_start(Utc::now());
    let period_end = next_month_start(period_start);
    let usage_summary = crate::usage::get_usage(&state.db, tenant_id, period_start, period_end)
        .await
        .map_err(|error| format!("Failed to load usage summary for {tenant_id}: {error}"))?;

    let configs = sqlx::query_as::<_, UsageAlertConfigRow>(
        r#"
        SELECT id, metric_type, threshold_percent, notification_channel
        FROM usage_alert_configs
        WHERE tenant_id = $1
          AND enabled = true
        ORDER BY threshold_percent ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load usage alert configs for {tenant_id}: {error}"))?;

    if configs.is_empty() {
        return Ok(0);
    }

    let webhook_url = load_usage_alert_webhook_url(state, tenant_id).await?;
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|error| format!("Failed to get Redis connection for usage alerts: {error}"))?;

    let mut alerts_triggered = 0_i64;

    for config in configs {
        let cooldown_key = format!(
            "alert:cooldown:{tenant_id}:{}:{}",
            config.metric_type, config.threshold_percent
        );
        let in_cooldown: bool = conn
            .exists(&cooldown_key)
            .await
            .map_err(|error| format!("Failed to check usage alert cooldown for {tenant_id}: {error}"))?;
        if in_cooldown {
            continue;
        }

        let Some((current_value, limit_value)) = resolve_usage_alert_metric(&usage_summary, &config.metric_type) else {
            continue;
        };

        let current_percent = if limit_value > 0 {
            (current_value as f64 / limit_value as f64) * 100.0
        } else {
            0.0
        };
        if current_percent < f64::from(config.threshold_percent) {
            continue;
        }

        let delivered = send_usage_alert(
            state,
            client,
            tenant_id,
            webhook_url.as_deref(),
            &config,
            current_value,
            limit_value,
            current_percent,
        )
        .await;

        if !delivered {
            continue;
        }

        let _: () = conn
            .set_ex(&cooldown_key, "1", USAGE_ALERT_COOLDOWN_SECONDS)
            .await
            .map_err(|error| format!("Failed to set usage alert cooldown for {tenant_id}: {error}"))?;

        sqlx::query(
            r#"
            UPDATE usage_alert_configs
            SET last_triggered_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(config.id)
        .execute(&state.db)
        .await
        .map_err(|error| format!("Failed to update usage alert trigger time for {tenant_id}: {error}"))?;

        alerts_triggered += 1;
    }

    Ok(alerts_triggered)
}

fn resolve_usage_alert_metric(
    usage_summary: &crate::types::UsageSummary,
    metric_type: &str,
) -> Option<(i64, i64)> {
    match metric_type {
        "emails" => Some((usage_summary.emails_sent, usage_summary.emails_limit)),
        "api_calls" => Some((usage_summary.api_calls, usage_summary.api_calls_limit)),
        _ => None,
    }
}

async fn load_usage_alert_webhook_url(
    state: &AppState,
    tenant_id: &str,
) -> Result<Option<String>, String> {
    let row = sqlx::query_as::<_, TenantAlertSettingsRow>(
        r#"
        SELECT COALESCE(settings, '{}'::jsonb) AS settings
        FROM tenants
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load tenant settings for {tenant_id}: {error}"))?;

    Ok(row.and_then(|row| {
        row.settings
            .get("webhookUrl")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }))
}

async fn send_usage_alert(
    state: &AppState,
    client: &Client,
    tenant_id: &str,
    webhook_url: Option<&str>,
    config: &UsageAlertConfigRow,
    current_value: i64,
    limit_value: i64,
    current_percent: f64,
) -> bool {
    let email_enabled = matches!(config.notification_channel.as_str(), "email" | "both");
    let webhook_enabled = matches!(config.notification_channel.as_str(), "webhook" | "both")
        && webhook_url.is_some();
    if !email_enabled && !webhook_enabled {
        return false;
    }

    let rounded_percent = current_percent.round() as i64;
    let email_payload = json!({
        "type": "usage_alert",
        "metricType": config.metric_type,
        "thresholdPercent": config.threshold_percent,
        "currentPercent": rounded_percent,
        "currentValue": current_value,
        "limitValue": limit_value,
    });

    let webhook_payload = json!({
        "event": "usage.threshold_reached",
        "data": {
            "metricType": config.metric_type,
            "thresholdPercent": config.threshold_percent,
            "currentPercent": rounded_percent,
            "currentValue": current_value,
            "limitValue": limit_value,
        },
        "timestamp": Utc::now().to_rfc3339(),
    });

    let mut delivered = false;

    if email_enabled {
        match sqlx::query(
            r#"
            INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
            VALUES (gen_random_uuid(), $1, 'usage_alert', $2, 'pending', NOW())
            "#,
        )
        .bind(tenant_id)
        .bind(&email_payload)
        .execute(&state.db)
        .await
        {
            Ok(_) => delivered = true,
            Err(error) => warn!(tenant_id = %tenant_id, error = %error, "failed to enqueue usage alert email"),
        }
    }

    if let Some(webhook_url) = webhook_url.filter(|_| webhook_enabled) {
        match client.post(webhook_url).json(&webhook_payload).send().await {
            Ok(response) if response.status().is_success() => {
                delivered = true;
            }
            Ok(response) => {
                warn!(
                    tenant_id = %tenant_id,
                    status = %response.status(),
                    webhook_url = %webhook_url,
                    "usage alert webhook returned non-success status"
                );
            }
            Err(error) => {
                warn!(tenant_id = %tenant_id, error = %error, webhook_url = %webhook_url, "failed to send usage alert webhook");
            }
        }
    }

    delivered
}

fn month_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now.with_day(1)
        .and_then(|date| date.with_hour(0))
        .and_then(|date| date.with_minute(0))
        .and_then(|date| date.with_second(0))
        .and_then(|date| date.with_nanosecond(0))
        .unwrap_or(now)
}

fn next_month_start(period_start: DateTime<Utc>) -> DateTime<Utc> {
    let shifted = period_start + chrono::Days::new(32);
    month_start(shifted)
}

fn day_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now.with_hour(0)
        .and_then(|date| date.with_minute(0))
        .and_then(|date| date.with_second(0))
        .and_then(|date| date.with_nanosecond(0))
        .unwrap_or(now)
}

fn next_day_start(now: DateTime<Utc>) -> DateTime<Utc> {
    day_start(now) + chrono::Days::new(1)
}

async fn process_monthly_sla_credits(state: &AppState) -> Result<SlaCreditSweepResult, String> {
    let current_month_start = month_start(Utc::now());
    let period_start = month_start(current_month_start - chrono::Days::new(1));
    let period_month = period_start.date_naive();
    let period_end = current_month_start;

    let candidates = sqlx::query_as::<_, SlaMetricCandidateRow>(
        r#"
        SELECT sm.tenant_id,
               sm.uptime_percent::double precision AS uptime_percent,
               p.features
        FROM sla_metrics sm
        JOIN tenants t ON t.id = sm.tenant_id
        JOIN plans p ON p.name = t.plan
        WHERE sm.period_month = $1
          AND t.status = 'active'
        ORDER BY sm.tenant_id
        "#,
    )
    .bind(period_month)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load SLA metric candidates: {error}"))?;

    let mut credits_created = 0_i64;
    for candidate in &candidates {
        if !feature_flag_enabled(&candidate.features, &["slaGuarantee", "sla_guarantee"]) {
            continue;
        }

        if candidate.uptime_percent >= SLA_AVAILABILITY_TARGET {
            continue;
        }

        let breach_percent = SLA_AVAILABILITY_TARGET - candidate.uptime_percent;
        let credit_percent = sla_credit_percentage_for_breach(breach_percent);
        if credit_percent == 0 {
            continue;
        }

        let invoice_amount_cents: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(amount_cents), 0)::bigint
            FROM invoices
            WHERE tenant_id = $1
              AND period_start >= $2
              AND period_end <= $3
            "#,
        )
        .bind(&candidate.tenant_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_one(&state.db)
        .await
        .map_err(|error| format!("Failed to load invoice total for SLA credits {}: {error}", candidate.tenant_id))?;

        let credit_amount = ((invoice_amount_cents as f64) * (credit_percent as f64 / 100.0)).round() as i64;
        if credit_amount <= 0 {
            continue;
        }

        let created: bool = sqlx::query_scalar(
            r#"
            WITH existing_credit AS (
                SELECT id
                FROM sla_credits
                WHERE tenant_id = $1
                  AND period_month = $2
                LIMIT 1
            ),
            insert_credit AS (
                INSERT INTO sla_credits (
                    id,
                    tenant_id,
                    period_month,
                    breach_percent,
                    credit_percent,
                    credit_amount,
                    currency,
                    status,
                    created_at
                )
                SELECT gen_random_uuid(), $1, $2, $3, $4, $5, 'USD', 'pending', NOW()
                WHERE NOT EXISTS (SELECT 1 FROM existing_credit)
                RETURNING id
            )
            SELECT EXISTS (SELECT 1 FROM insert_credit)
            "#,
        )
        .bind(&candidate.tenant_id)
        .bind(period_month)
        .bind(breach_percent)
        .bind(credit_percent)
        .bind(credit_amount)
        .fetch_one(&state.db)
        .await
        .map_err(|error| format!("Failed to upsert SLA credit for {}: {error}", candidate.tenant_id))?;

        if created {
            credits_created += 1;
        }
    }

    Ok(SlaCreditSweepResult {
        tenants_checked: i64::try_from(candidates.len()).unwrap_or(i64::MAX),
        credits_created,
    })
}

fn feature_flag_enabled(features: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        features
            .get(*key)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    })
}

fn sla_credit_percentage_for_breach(breach_percent: f64) -> i32 {
    if breach_percent >= 5.0 {
        100
    } else if breach_percent >= 1.0 {
        50
    } else if breach_percent >= 0.5 {
        25
    } else if breach_percent >= 0.1 {
        10
    } else {
        0
    }
}

async fn process_dedicated_ip_billing(
    state: &AppState,
    client: &Client,
) -> Result<DedicatedIpSyncResult, String> {
    let charged = process_pending_dedicated_ip_charges(state, client).await?;
    let canceled = process_pending_dedicated_ip_cancels(state, client).await?;

    Ok(DedicatedIpSyncResult { charged, canceled })
}

async fn process_pending_dedicated_ip_charges(
    state: &AppState,
    client: &Client,
) -> Result<i64, String> {
    let Some(price_id) = dedicated_ip_price_id() else {
        return Ok(0);
    };

    let rows = match sqlx::query_as::<_, DedicatedIpPendingRow>(
        r#"
        SELECT id, tenant_id, ip_address, stripe_subscription_item_id
        FROM dedicated_ips
        WHERE billing_status = 'pending_charge'
          AND (billing_retry_after IS NULL OR billing_retry_after <= NOW())
        ORDER BY created_at ASC
        LIMIT 50
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_missing_table_error(&error) => {
            log_missing_dedicated_ip_table_once();
            return Ok(0);
        }
        Err(error) => {
            return Err(format!("Failed to load pending dedicated IP charges: {error}"));
        }
    };

    let mut processed = 0_i64;
    for row in rows {
        match charge_dedicated_ip(state, client, &row, &price_id).await {
            Ok(()) => processed += 1,
            Err(error_message) => {
                warn!(tenant_id = %row.tenant_id, ip_id = %row.id, ip_address = %row.ip_address, error = %error_message, "failed to create dedicated IP Stripe subscription item");
            }
        }
    }

    Ok(processed)
}

async fn process_pending_dedicated_ip_cancels(
    state: &AppState,
    client: &Client,
) -> Result<i64, String> {
    let rows = match sqlx::query_as::<_, DedicatedIpPendingRow>(
        r#"
        SELECT id, tenant_id, ip_address, stripe_subscription_item_id
        FROM dedicated_ips
        WHERE billing_status = 'pending_cancel'
        ORDER BY updated_at ASC
        LIMIT 50
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_missing_table_error(&error) => {
            log_missing_dedicated_ip_table_once();
            return Ok(0);
        }
        Err(error) => {
            return Err(format!("Failed to load pending dedicated IP cancels: {error}"));
        }
    };

    let mut processed = 0_i64;
    for row in rows {
        match cancel_dedicated_ip_billing(state, client, &row).await {
            Ok(()) => processed += 1,
            Err(error_message) => {
                warn!(tenant_id = %row.tenant_id, ip_id = %row.id, ip_address = %row.ip_address, error = %error_message, "failed to cancel dedicated IP Stripe subscription item");
            }
        }
    }

    Ok(processed)
}

async fn charge_dedicated_ip(
    state: &AppState,
    client: &Client,
    row: &DedicatedIpPendingRow,
    price_id: &str,
) -> Result<(), String> {
    let subscription = sqlx::query_as::<_, TenantStripeSubscriptionRow>(
        r#"
        SELECT stripe_subscription_id
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&row.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load tenant Stripe subscription: {error}"))?;

    let Some(subscription) = subscription else {
        update_dedicated_ip_retry_metadata(state, &row.id).await;
        return Err("No active Stripe subscription for tenant".to_string());
    };

    let response = match dedicated_ip_subscription_item_create(
        client,
        &subscription.stripe_subscription_id,
        price_id,
        &row.id,
        &row.tenant_id,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            update_dedicated_ip_retry_metadata(state, &row.id).await;
            return Err(error);
        }
    };

    sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_status = 'active',
            stripe_subscription_item_id = $2,
            billing_started_at = NOW(),
            billing_failure_count = 0,
            billing_retry_after = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&row.id)
    .bind(response.id)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to mark dedicated IP billing active: {error}"))?;

    Ok(())
}

async fn cancel_dedicated_ip_billing(
    state: &AppState,
    client: &Client,
    row: &DedicatedIpPendingRow,
) -> Result<(), String> {
    if let Some(subscription_item_id) = &row.stripe_subscription_item_id {
        dedicated_ip_subscription_item_delete(client, subscription_item_id).await?;
    }

    sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_status = 'canceled',
            billing_ended_at = NOW(),
            billing_retry_after = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&row.id)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to finalize dedicated IP billing cancel: {error}"))?;

    Ok(())
}

fn dedicated_ip_price_id() -> Option<String> {
    std::env::var("STRIPE_DEDICATED_IP_PRICE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn dedicated_ip_subscription_item_create(
    client: &Client,
    subscription_id: &str,
    price_id: &str,
    ip_id: &str,
    tenant_id: &str,
) -> Result<StripeSubscriptionItemResponse, String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let form = vec![
        ("subscription", subscription_id.to_string()),
        ("price", price_id.to_string()),
        ("quantity", "1".to_string()),
        ("proration_behavior", "create_prorations".to_string()),
        ("metadata[apexmail_ip_id]", ip_id.to_string()),
        ("metadata[apexmail_tenant_id]", tenant_id.to_string()),
        ("metadata[type]", "dedicated_ip_addon".to_string()),
    ];

    let response = client
        .post(format!("{}/v1/subscription_items", stripe_api_base_url()))
        .bearer_auth(secret_key)
        .header("Idempotency-Key", format!("apexmail_ip_charge_{ip_id}"))
        .form(&form)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    decode_stripe_response(response).await
}

async fn dedicated_ip_subscription_item_delete(
    client: &Client,
    subscription_item_id: &str,
) -> Result<(), String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let form = [("proration_behavior", "create_prorations")];
    let response = client
        .delete(format!(
            "{}/v1/subscription_items/{subscription_item_id}",
            stripe_api_base_url()
        ))
        .bearer_auth(secret_key)
        .form(&form)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status.as_u16() == 404 || body.contains("resource_missing") {
        return Ok(());
    }

    Err(format!("Stripe returned {status}: {body}"))
}

fn is_missing_table_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db_error| db_error.code())
        .is_some_and(|code| code == "42P01")
}

fn log_missing_dedicated_ip_table_once() {
    if DEDICATED_IP_TABLE_MISSING_LOGGED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        warn!(table = "dedicated_ips", "dedicated IP table missing; skipping dedicated IP billing sync until migrations are applied");
    }
}

async fn update_dedicated_ip_retry_metadata(state: &AppState, ip_id: &str) {
    if let Err(error) = sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_failure_count = COALESCE(billing_failure_count, 0) + 1,
            billing_retry_after = NOW() + (
                LEAST(POWER(2, LEAST(COALESCE(billing_failure_count, 0), 5)), 30) || ' minutes'
            )::interval,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(ip_id)
    .execute(&state.db)
    .await
    {
        warn!(ip_id = %ip_id, error = %error, "failed to update dedicated IP retry metadata");
    }
}

async fn process_cost_margin_checks(state: &AppState) -> Result<CostMarginSweepResult, String> {
    let tenant_ids: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM tenants
        WHERE status = 'active'
        ORDER BY id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load active tenants for cost checks: {error}"))?;

    let mut warnings = 0_i64;
    let mut critical = 0_i64;

    for tenant_id in &tenant_ids {
        match check_tenant_cost_margin(state, tenant_id).await {
            Ok(CostMarginStatus::Warning) => warnings += 1,
            Ok(CostMarginStatus::Critical) => critical += 1,
            Ok(CostMarginStatus::Healthy) => {}
            Err(error_message) => {
                warn!(tenant_id = %tenant_id, error = %error_message, "failed to evaluate tenant cost margin");
            }
        }
    }

    Ok(CostMarginSweepResult {
        checked: i64::try_from(tenant_ids.len()).unwrap_or(i64::MAX),
        warnings,
        critical,
    })
}

async fn check_tenant_cost_margin(
    state: &AppState,
    tenant_id: &str,
) -> Result<CostMarginStatus, String> {
    let period_start = month_start(Utc::now());
    let period_end = next_month_start(period_start);

    let summary = sqlx::query_as::<_, TenantCostSummaryRow>(
        r#"
        SELECT
            COALESCE(SUM(storage_cost), 0)::bigint AS storage_cost,
            COALESCE(SUM(bandwidth_cost), 0)::bigint AS bandwidth_cost,
            COALESCE(SUM(compute_cost), 0)::bigint AS compute_cost,
            COALESCE(SUM(dedicated_ip_cost), 0)::bigint AS dedicated_ip_cost,
            COALESCE(SUM(total_cost), 0)::bigint AS total_cost,
            COALESCE(SUM(revenue), 0)::bigint AS revenue
        FROM tenant_costs
        WHERE tenant_id = $1
          AND recorded_at >= $2
          AND recorded_at < $3
        "#,
    )
    .bind(tenant_id)
    .bind(period_start.date_naive())
    .bind(period_end.date_naive())
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to load tenant cost summary for {tenant_id}: {error}"))?;

    if summary.total_cost == 0 && summary.revenue == 0 {
        cache_cost_margin_status(state, tenant_id, CostMarginStatus::Healthy, None).await;
        return Ok(CostMarginStatus::Healthy);
    }

    let margin_percent = if summary.revenue > 0 {
        ((summary.revenue - summary.total_cost) as f64 / summary.revenue as f64) * 100.0
    } else {
        0.0
    };

    let status = if margin_percent < COST_MARGIN_CRITICAL_THRESHOLD {
        let alert_type = if margin_percent < 0.0 {
            "negative_margin"
        } else {
            "low_margin"
        };
        create_cost_margin_alert(
            state,
            tenant_id,
            alert_type,
            COST_MARGIN_CRITICAL_THRESHOLD,
            margin_percent,
            &summary,
        )
        .await?;
        apply_cost_throttling(state, tenant_id).await;
        CostMarginStatus::Critical
    } else if margin_percent < COST_MARGIN_WARNING_THRESHOLD {
        create_cost_margin_alert(
            state,
            tenant_id,
            "low_margin",
            COST_MARGIN_WARNING_THRESHOLD,
            margin_percent,
            &summary,
        )
        .await?;
        CostMarginStatus::Warning
    } else {
        CostMarginStatus::Healthy
    };

    cache_cost_margin_status(state, tenant_id, status, Some(margin_percent)).await;
    Ok(status)
}

async fn create_cost_margin_alert(
    state: &AppState,
    tenant_id: &str,
    alert_type: &str,
    threshold: f64,
    margin_percent: f64,
    summary: &TenantCostSummaryRow,
) -> Result<(), String> {
    let details = json!({
        "threshold": threshold,
        "actual": margin_percent,
        "costs": {
            "storage": summary.storage_cost,
            "bandwidth": summary.bandwidth_cost,
            "compute": summary.compute_cost,
            "dedicatedIp": summary.dedicated_ip_cost,
            "total": summary.total_cost,
        },
        "revenue": summary.revenue,
    });

    sqlx::query(
        r#"
        WITH existing_alert AS (
            SELECT id
            FROM cost_alerts
            WHERE tenant_id = $1
              AND alert_type = $2
              AND resolved_at IS NULL
            LIMIT 1
        ),
        insert_alert AS (
            INSERT INTO cost_alerts (id, tenant_id, alert_type, margin_percent, details, created_at)
            SELECT gen_random_uuid(), $1, $2, $3, $4, NOW()
            WHERE NOT EXISTS (SELECT 1 FROM existing_alert)
            RETURNING id
        )
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        SELECT gen_random_uuid(), $1, 'cost_alert', $4, 'pending', NOW()
        WHERE EXISTS (SELECT 1 FROM insert_alert)
        "#,
    )
    .bind(tenant_id)
    .bind(alert_type)
    .bind(margin_percent)
    .bind(&details)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to create cost alert for {tenant_id}: {error}"))?;

    Ok(())
}

async fn apply_cost_throttling(state: &AppState, tenant_id: &str) {
    match state.redis.get().await {
        Ok(mut conn) => {
            let throttle_payload = json!({
                "appliedAt": Utc::now().to_rfc3339(),
                "reason": "low_margin",
            })
            .to_string();

            let current_limit: Option<String> = match conn.get(format!("rate:limit:{tenant_id}")).await {
                Ok(value) => value,
                Err(error) => {
                    warn!(tenant_id = %tenant_id, error = %error, "failed to read current tenant rate limit during cost throttling");
                    None
                }
            };
            let throttled_limit = current_limit
                .as_deref()
                .and_then(|value| value.parse::<i64>().ok())
                .map(|value| (value / 2).max(1))
                .unwrap_or(50);

            let mut pipeline = redis::pipe();
            pipeline
                .set_ex(format!("cost:throttle:{tenant_id}"), throttle_payload, 24 * 60 * 60)
                .ignore()
                .set_ex(
                    format!("rate:limit:{tenant_id}:throttled"),
                    throttled_limit.to_string(),
                    24 * 60 * 60,
                )
                .ignore();

            if let Err(error) = pipeline.query_async::<()>(&mut conn).await {
                warn!(tenant_id = %tenant_id, error = %error, "failed to persist cost throttling state");
            }
        }
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to get Redis connection for cost throttling");
        }
    }
}

async fn cache_cost_margin_status(
    state: &AppState,
    tenant_id: &str,
    status: CostMarginStatus,
    margin_percent: Option<f64>,
) {
    match state.redis.get().await {
        Ok(mut conn) => {
            let payload = json!({
                "status": status.as_str(),
                "margin": margin_percent,
                "checkedAt": Utc::now().to_rfc3339(),
            })
            .to_string();
            let cache_result: Result<(), redis::RedisError> = conn.set_ex(
                format!("cost:status:{tenant_id}"),
                payload,
                60 * 60,
            ).await;
            if let Err(error) = cache_result {
                warn!(tenant_id = %tenant_id, error = %error, "failed to cache cost margin status");
            }
        }
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to get Redis connection for cost status cache");
        }
    }
}

async fn process_expired_wallet_reservations(state: &AppState) -> Result<i64, String> {
    let rows = sqlx::query_as::<_, ExpiredWalletReservationRow>(
        r#"
        WITH expired_reservations AS (
            SELECT id, tenant_id, amount
            FROM wallet_reservations
            WHERE status IN ('pending', 'active')
              AND captured_at IS NULL
              AND released_at IS NULL
              AND expires_at < NOW()
            FOR UPDATE SKIP LOCKED
        ),
        released_reservations AS (
            UPDATE wallet_reservations wr
            SET status = 'released', released_at = NOW()
            FROM expired_reservations er
            WHERE wr.id = er.id
            RETURNING er.tenant_id, er.amount
        ),
        released_totals AS (
            SELECT tenant_id, COALESCE(SUM(amount), 0)::bigint AS total_amount
            FROM released_reservations
            GROUP BY tenant_id
        ),
        wallet_updates AS (
            UPDATE wallets w
            SET reserved = GREATEST(0, w.reserved - rt.total_amount::integer),
                updated_at = NOW()
            FROM released_totals rt
            WHERE w.tenant_id = rt.tenant_id
            RETURNING w.tenant_id
        )
        SELECT wu.tenant_id,
               COALESCE((SELECT COUNT(*)::bigint FROM released_reservations), 0) AS released_count
        FROM wallet_updates wu
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to release expired wallet reservations: {error}"))?;

    let released_count = rows.first().map(|row| row.released_count).unwrap_or(0);
    if released_count == 0 {
        return Ok(0);
    }

    if let Ok(mut conn) = state.redis.get().await {
        let tenant_ids: Vec<String> = rows.into_iter().map(|row| row.tenant_id).collect();
        if !tenant_ids.is_empty() {
            let keys: Vec<String> = tenant_ids
                .into_iter()
                .map(|tenant_id| format!("wallet:balance:{tenant_id}"))
                .collect();
            if let Err(error) = delete_redis_keys(&mut conn, &keys).await {
                warn!(error = %error, "failed to clear wallet balance cache after releasing reservations");
            }
        }
    }

    Ok(released_count)
}

#[derive(Debug, FromRow)]
struct ExpiredWalletReservationRow {
    tenant_id: String,
    released_count: i64,
}

async fn mark_payment_recovered(state: &AppState, tenant_id: &str) -> Result<(), String> {
    sqlx::query(
        r#"
        WITH update_dunning AS (
            UPDATE dunning_records
            SET status = 'healthy',
                failed_payment_count = 0,
                first_failed_at = NULL,
                last_failed_at = NULL,
                next_retry_at = NULL,
                suspended_at = NULL,
                grace_period_ends_at = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING tenant_id
        ),
        log_recovery AS (
            INSERT INTO dunning_events (id, tenant_id, event_type, created_at)
            VALUES (gen_random_uuid(), $1, 'payment_recovered', NOW())
            RETURNING tenant_id
        ),
        reactivate_tenant AS (
            UPDATE tenants
            SET status = 'active', updated_at = NOW()
            WHERE id = $1
              AND NOT EXISTS (
                SELECT 1
                FROM abuse_reports ar
                WHERE ar.tenant_id = $1
                  AND ar.status IN ('open', 'investigating', 'confirmed')
              )
            RETURNING id
        )
        SELECT 1
        "#,
    )
    .bind(tenant_id)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to mark payment recovered for {tenant_id}: {error}"))?;

    let released_count: i64 = sqlx::query_scalar(
        r#"
        WITH updated AS (
            UPDATE messages
            SET status = 'queued', updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'dunning_queued'
            RETURNING id
        )
        SELECT COUNT(*)::bigint FROM updated
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if released_count > 0 {
        info!(tenant_id = %tenant_id, released_count, "released queued messages after payment recovery");
    }

    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = format!("dunning:status:{tenant_id}");
        let delete_result: Result<i64, _> = conn.del(&cache_key).await;
        if let Err(error) = delete_result {
            warn!(tenant_id = %tenant_id, error = %error, "failed to clear cached dunning status");
        }
    }

    Ok(())
}

async fn cleanup_stuck_subscription_sagas(state: &AppState) -> Result<i64, String> {
    let timeout_minutes = std::env::var("SAGA_TIMEOUT_MINUTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(60);

    sqlx::query_scalar::<_, i64>(
        &format!(
            r#"
            WITH updated AS (
                UPDATE subscription_change_saga
                SET status = 'failed',
                    error = COALESCE(error, 'Timed out waiting for completion'),
                    updated_at = NOW()
                WHERE status IN ('pending', 'stripe_completed')
                  AND updated_at < NOW() - INTERVAL '{timeout_minutes} minutes'
                RETURNING id
            )
            SELECT COUNT(*)::bigint AS cleaned FROM updated
            "#
        ),
    )
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to clean stuck subscription sagas: {error}"))
}

fn stripe_api_base_url() -> String {
    std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into())
}

async fn stripe_get_json<T: DeserializeOwned>(
    client: &Client,
    path: &str,
    query: &[(&str, String)],
) -> Result<T, String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let response = client
        .get(format!("{}{}", stripe_api_base_url(), path))
        .bearer_auth(secret_key)
        .query(query)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    decode_stripe_response(response).await
}

async fn stripe_post_json<T: DeserializeOwned>(client: &Client, path: &str) -> Result<T, String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let response = client
        .post(format!("{}{}", stripe_api_base_url(), path))
        .bearer_auth(secret_key)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    decode_stripe_response(response).await
}

async fn decode_stripe_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, String> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Stripe returned {status}: {body}"));
    }

    response
        .json::<T>()
        .await
        .map_err(|error| format!("Stripe response decode failed: {error}"))
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceListResponse {
    data: Vec<StripeInvoiceSummary>,
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceSummary {
    id: String,
}