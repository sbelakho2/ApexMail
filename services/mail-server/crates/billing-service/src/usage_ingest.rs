//! Usage-metering completeness: ingest API + sweep-derived aggregates +
//! reserved-vs-delivered reconciliation.
//!
//! Before this module only `emails_sent` was ever metered (api-server
//! messages.rs). The PAYG line items for `api_calls`, `emails_delivered`,
//! `webhooks_delivered`, `dedicated_ip_hours`, `storage_gb_hours` and
//! `bandwidth_gb` were structurally zero. This module closes that gap
//! without any cross-crate edits:
//!
//! * [`ingest_usage_batch`] — a service-authenticated batch ingest endpoint
//!   (`POST /usage/ingest`) the edge / worker-processors can call for any
//!   event type (notably `api_calls`, which has no platform source table —
//!   see the api-server middleware handoff in the module docs of
//!   [`sweep_derived_usage`]).
//! * [`sweep_derived_usage`] — a maintenance sweep that derives per-tenant
//!   per-day aggregates from the platform's own state tables:
//!
//! | event_type           | source table(s)                     | derivation                                    |
//! |----------------------|--------------------------------------|-----------------------------------------------|
//! | `emails_delivered`   | `email_queue` ∪ `email_delivery_log` | terminal `status='sent'` per `sent_at` day, UNION per-attempt `success` rows per `attempted_at` day, deduplicated per email (queue-only fallback when the log table is absent) |
//! | `webhooks_delivered` | `webhook_events`                     | rows with `delivery_status='delivered'`/day   |
//! | `dedicated_ip_hours` | `dedicated_ips`                      | billing-interval overlap with the day (h)     |
//! | `storage_gb_hours`   | `tenant_costs`                       | `storage_gb * 24` per recorded day            |
//! | `bandwidth_gb`       | `tenant_costs`                       | `bandwidth_gb` per recorded day               |
//! | `api_calls`          | *(no source table)*                  | ingest endpoint only (handoff documented)     |
//!
//! Every derived aggregate is idempotent: a marker row in
//! `metering_daily_markers` keyed on `(tenant_id, event_type, day, source)`
//! (migration 104) is inserted in the same transaction as the metering
//! event, so re-runs and crash-restarts can never double-record a day.
//!
//! Fractional quantities (hours, GB) are recorded as whole units rounded
//! half-up (SQL `ROUND` on positive numerics), matching the platform's
//! other money/quantity math.

use std::collections::HashMap;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::routes::append_audit_log;
use crate::types::MeterEventType;
use crate::usage::record_usage;

/// Maximum number of events accepted by one ingest batch call.
pub const INGEST_BATCH_LIMIT: usize = 1_000;

/// Marker source identifier for the derived emails_delivered aggregate.
/// One source id covers BOTH derivation paths (combined queue+delivery-log,
/// and the queue-only fallback): a day is recorded exactly once even if the
/// deployment's available source tables change between runs.
pub const SOURCE_EMAIL_DELIVERY: &str = "email_delivery_sweep";
pub const SOURCE_WEBHOOK_EVENTS: &str = "webhook_events_sweep";
pub const SOURCE_DEDICATED_IPS: &str = "dedicated_ips_sweep";
pub const SOURCE_TENANT_COSTS: &str = "tenant_costs_sweep";

// ---------------------------------------------------------------------------
// Ingest API (edge-callable)
// ---------------------------------------------------------------------------

/// One event in a `POST /usage/ingest` batch.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IngestEvent {
    pub tenant_id: String,
    pub event_type: MeterEventType,
    #[serde(default = "default_quantity")]
    pub quantity: i64,
    /// Optional caller-supplied idempotency key. When omitted, each batch
    /// event gets a fresh UUID (fire-and-forget semantics).
    #[serde(default)]
    pub event_id: Option<Uuid>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

fn default_quantity() -> i64 {
    1
}

/// Outcome of one batch ingest call.
#[derive(Debug, Default, serde::Serialize)]
pub struct IngestBatchResult {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
    pub errors: Vec<String>,
}

/// Record a batch of metering events through the standard idempotent
/// [`record_usage`] path (Redis dedup + DB `ON CONFLICT (id) DO NOTHING` +
/// audit trail). Used by the `POST /usage/ingest` route; the edge/worker
/// calls this for event types that have no derivable platform source table
/// (today: `api_calls`).
pub async fn ingest_usage_batch(
    pool: &PgPool,
    redis: &deadpool_redis::Pool,
    events: &[IngestEvent],
) -> IngestBatchResult {
    let mut result = IngestBatchResult::default();
    let error_display_limit = 5;

    for event in events {
        match record_usage(
            pool,
            redis,
            &event.tenant_id,
            event.event_type,
            event.quantity,
            event.event_id,
            event.metadata.clone(),
        )
        .await
        {
            Ok(true) => result.accepted += 1,
            Ok(false) => result.duplicates += 1,
            Err(error) => {
                result.rejected += 1;
                if result.errors.len() < error_display_limit {
                    result.errors.push(format!(
                        "tenant={} type={} quantity={}: {error}",
                        event.tenant_id,
                        crate::usage::meter_event_type_str(event.event_type),
                        event.quantity
                    ));
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Derived daily aggregates (maintenance sweep)
// ---------------------------------------------------------------------------

/// Per-source status of one sweep run.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct DerivedUsageSweepResult {
    pub day: String,
    pub emails_delivered: i64,
    pub webhooks_delivered: i64,
    pub dedicated_ip_hours: i64,
    pub storage_gb_hours: i64,
    pub bandwidth_gb: i64,
    /// Sources whose backing table does not exist in this deployment.
    pub skipped_sources: Vec<String>,
}

/// Row shape shared by all "count per tenant for a day" queries.
#[derive(sqlx::FromRow)]
struct TenantCountRow {
    tenant_id: String,
    quantity: i64,
}

/// The last fully-closed UTC day relative to `now` (a day is only derivable
/// once it has ended, so the sweep always targets yesterday).
pub fn sweep_target_day(now: DateTime<Utc>) -> NaiveDate {
    (now - Duration::days(1)).date_naive()
}

/// Deterministic event id for a derived aggregate: SHA-256 of
/// `tenant|event_type|day|source` mapped into a UUID (same construction as
/// `normalize_metering_event_id` in maintenance.rs). Re-runs derive the
/// same id, and the metering_events PK provides a second idempotency layer
/// behind the marker row.
pub fn derived_event_id(tenant_id: &str, event_type: &str, day: NaiveDate, source: &str) -> Uuid {
    let key = format!("{tenant_id}|{event_type}|{day}|{source}");
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn day_bounds(day: NaiveDate) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let start = day
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();
    let end = (day + Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();
    (start, end)
}

/// Record one derived daily aggregate idempotently: marker + metering event
/// + audit entry in a single transaction. Returns `Ok(true)` when the
/// aggregate was newly recorded, `Ok(false)` when the (tenant, event_type,
/// day, source) marker already exists.
async fn record_derived_daily_aggregate(
    pool: &PgPool,
    tenant_id: &str,
    event_type: &str,
    day: NaiveDate,
    source: &str,
    quantity: i64,
    recorded_at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let event_id = derived_event_id(tenant_id, event_type, day, source);
    let metadata = serde_json::json!({
        "source": source,
        "derived": true,
        "day": day.to_string(),
    });

    let mut tx = pool.begin().await?;

    // 1. Marker first — UNIQUE(tenant, event_type, day, source) makes this
    //    the idempotency gate for the whole aggregate. Zero-quantity days
    //    still get a marker so the sweep does not re-derive emptiness.
    let marker = sqlx::query(
        r#"
        INSERT INTO metering_daily_markers (tenant_id, event_type, day, source, quantity)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (tenant_id, event_type, day, source) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(event_type)
    .bind(day)
    .bind(source)
    .bind(quantity.max(0))
    .execute(&mut *tx)
    .await?;

    if marker.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    if quantity <= 0 {
        // Marker-only row: nothing to meter.
        tx.commit().await?;
        return Ok(false);
    }

    // 2. Metering event (deterministic id — ON CONFLICT is the belt to the
    //    marker's braces).
    sqlx::query(
        r#"
        INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(event_id)
    .bind(tenant_id)
    .bind(event_type)
    .bind(quantity)
    .bind(recorded_at)
    .bind(&metadata)
    .execute(&mut *tx)
    .await?;

    // 3. Immutable audit record. An aggregate without its audit trail must
    //    not be silently committed — abort the whole transaction on failure.
    append_audit_log(
        &mut tx,
        tenant_id,
        "billing.metering_derived_aggregate_recorded",
        "metering_event",
        Some(&event_id.to_string()),
        json!({
            "eventType": event_type,
            "quantity": quantity,
            "day": day.to_string(),
            "source": source,
        }),
        recorded_at,
    )
    .await
    .map_err(sqlx::Error::Protocol)?;

    tx.commit().await?;
    Ok(true)
}

async fn record_tenant_counts(
    pool: &PgPool,
    event_type: &str,
    day: NaiveDate,
    source: &str,
    rows: Vec<TenantCountRow>,
    recorded_at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let mut recorded = 0_i64;
    for row in rows {
        if record_derived_daily_aggregate(
            pool,
            &row.tenant_id,
            event_type,
            day,
            source,
            row.quantity,
            recorded_at,
        )
        .await?
        {
            recorded += 1;
        }
    }
    Ok(recorded)
}

fn is_missing_table(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db_error| db_error.code())
        .is_some_and(|code| code == "42P01")
}

/// Derive `emails_delivered` for `day` from BOTH delivery-outcome tables:
/// outbound queue rows that reached terminal delivery success
/// (`status='sent'`, by `sent_at` day) UNION per-attempt successes in
/// `email_delivery_log` (by `attempted_at` day, tenant attributed via the
/// queue). The UNION deduplicates per email, so a delivery present in both
/// tables counts exactly once. When the delivery log does not exist in
/// this deployment, the derivation falls back to the queue alone — under
/// the SAME marker source, so a day can only ever be recorded once.
async fn sweep_emails_delivered(
    pool: &PgPool,
    day: NaiveDate,
    recorded_at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let (day_start, day_end) = day_bounds(day);

    let combined = sqlx::query_as::<_, TenantCountRow>(
        r#"
        WITH delivered AS (
            SELECT q.id, q.tenant_id
            FROM email_queue q
            WHERE q.status = 'sent'
              AND q.sent_at IS NOT NULL
              AND q.sent_at >= $1
              AND q.sent_at <  $2
              AND q.tenant_id IS NOT NULL
            UNION
            SELECT l.email_id, q.tenant_id
            FROM email_delivery_log l
            JOIN email_queue q ON q.id = l.email_id
            WHERE l.success = TRUE
              AND l.attempted_at >= $1
              AND l.attempted_at <  $2
              AND q.tenant_id IS NOT NULL
        )
        SELECT tenant_id::text AS tenant_id, COUNT(DISTINCT id)::bigint AS quantity
        FROM delivered
        GROUP BY tenant_id
        "#,
    )
    .bind(day_start)
    .bind(day_end)
    .fetch_all(pool)
    .await;

    let rows = match combined {
        Ok(rows) => rows,
        Err(error) if is_missing_table(&error) => {
            // No email_delivery_log (or no email_queue) here: derive from
            // the queue alone. If the queue is missing too this second
            // query fails 42P01 as well and the caller skips the source.
            sqlx::query_as::<_, TenantCountRow>(
                r#"
                SELECT tenant_id::text AS tenant_id, COUNT(*)::bigint AS quantity
                FROM email_queue
                WHERE status = 'sent'
                  AND sent_at IS NOT NULL
                  AND sent_at >= $1
                  AND sent_at <  $2
                  AND tenant_id IS NOT NULL
                GROUP BY tenant_id
                "#,
            )
            .bind(day_start)
            .bind(day_end)
            .fetch_all(pool)
            .await?
        }
        Err(error) => return Err(error),
    };

    record_tenant_counts(
        pool,
        "emails_delivered",
        day,
        SOURCE_EMAIL_DELIVERY,
        rows,
        recorded_at,
    )
    .await
}

/// Derive `webhooks_delivered` for `day`: webhook events that reached a
/// successful terminal delivery state, counted by `updated_at` day.
async fn sweep_webhooks_delivered(
    pool: &PgPool,
    day: NaiveDate,
    recorded_at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let (day_start, day_end) = day_bounds(day);
    let rows: Vec<TenantCountRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, COUNT(*)::bigint AS quantity
        FROM webhook_events
        WHERE delivery_status IN ('delivered', 'success')
          AND updated_at >= $1
          AND updated_at <  $2
        GROUP BY tenant_id
        "#,
    )
    .bind(day_start)
    .bind(day_end)
    .fetch_all(pool)
    .await?;

    record_tenant_counts(
        pool,
        "webhooks_delivered",
        day,
        SOURCE_WEBHOOK_EVENTS,
        rows,
        recorded_at,
    )
    .await
}

/// Derive `dedicated_ip_hours` for `day`: overlap (in whole hours, rounded
/// half-up) between the day and each dedicated IP's billing interval
/// `[billing_started_at, billing_ended_at)`. Only billable lifecycle states
/// count; `retired`/`canceled` rows with no overlap contribute nothing.
async fn sweep_dedicated_ip_hours(
    pool: &PgPool,
    day: NaiveDate,
    recorded_at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let (day_start, day_end) = day_bounds(day);
    let rows: Vec<TenantCountRow> = sqlx::query_as(
        r#"
        SELECT tenant_id::text AS tenant_id,
               SUM(ROUND(
                   EXTRACT(EPOCH FROM (
                       LEAST(COALESCE(billing_ended_at, $2), $2)
                       - GREATEST(billing_started_at, $1)
                   )) / 3600.0
               ))::bigint AS quantity
        FROM dedicated_ips
        WHERE billing_status IN ('included', 'pending_charge', 'active', 'pending_cancel')
          AND billing_started_at IS NOT NULL
          AND billing_started_at < $2
          AND COALESCE(billing_ended_at, $2) > $1
        GROUP BY tenant_id
        "#,
    )
    .bind(day_start)
    .bind(day_end)
    .fetch_all(pool)
    .await?;

    record_tenant_counts(
        pool,
        "dedicated_ip_hours",
        day,
        SOURCE_DEDICATED_IPS,
        rows,
        recorded_at,
    )
    .await
}

/// Derive `storage_gb_hours` (`storage_gb * 24`) and `bandwidth_gb` for
/// `day` from the platform's own cost-tracking table (`tenant_costs`,
/// migration 022). DECIMAL values are rounded half-up to whole units
/// SQL-side.
async fn sweep_tenant_cost_quantities(
    pool: &PgPool,
    day: NaiveDate,
    recorded_at: DateTime<Utc>,
) -> Result<(i64, i64), sqlx::Error> {
    let storage_rows: Vec<TenantCountRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, ROUND(storage_gb * 24)::bigint AS quantity
        FROM tenant_costs
        WHERE recorded_at = $1
          AND storage_gb > 0
        "#,
    )
    .bind(day)
    .fetch_all(pool)
    .await?;

    let storage_recorded = record_tenant_counts(
        pool,
        "storage_gb_hours",
        day,
        SOURCE_TENANT_COSTS,
        storage_rows,
        recorded_at,
    )
    .await?;

    let bandwidth_rows: Vec<TenantCountRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, ROUND(bandwidth_gb)::bigint AS quantity
        FROM tenant_costs
        WHERE recorded_at = $1
          AND bandwidth_gb > 0
        "#,
    )
    .bind(day)
    .fetch_all(pool)
    .await?;

    let bandwidth_recorded = record_tenant_counts(
        pool,
        "bandwidth_gb",
        day,
        SOURCE_TENANT_COSTS,
        bandwidth_rows,
        recorded_at,
    )
    .await?;

    Ok((storage_recorded, bandwidth_recorded))
}

/// Run every derived-aggregate sweep for the last fully-closed UTC day.
/// Sources whose backing table is missing in this deployment are reported
/// in `skipped_sources` instead of failing the sweep (same tolerance as the
/// dedicated-IP billing sync).
///
/// `api_calls` is deliberately NOT derived here: the platform has no
/// request-log table. The edge must POST counts to `POST /usage/ingest`
/// with `{tenantId, eventType: "api_calls", quantity, eventId}` — the
/// api-server middleware handoff is documented in this crate's report.
pub async fn sweep_derived_usage(
    pool: &PgPool,
    now: DateTime<Utc>,
) -> Result<DerivedUsageSweepResult, String> {
    let day = sweep_target_day(now);
    let recorded_at = now;
    let mut result = DerivedUsageSweepResult {
        day: day.to_string(),
        ..DerivedUsageSweepResult::default()
    };

    match sweep_emails_delivered(pool, day, recorded_at).await {
        Ok(count) => result.emails_delivered = count,
        Err(error) if is_missing_table(&error) => {
            result.skipped_sources.push("email_queue".into());
        }
        Err(error) => return Err(format!("emails_delivered sweep failed: {error}")),
    }

    match sweep_webhooks_delivered(pool, day, recorded_at).await {
        Ok(count) => result.webhooks_delivered = count,
        Err(error) if is_missing_table(&error) => {
            result.skipped_sources.push("webhook_events".into());
        }
        Err(error) => return Err(format!("webhooks_delivered sweep failed: {error}")),
    }

    match sweep_dedicated_ip_hours(pool, day, recorded_at).await {
        Ok(count) => result.dedicated_ip_hours = count,
        Err(error) if is_missing_table(&error) => {
            result.skipped_sources.push("dedicated_ips".into());
        }
        Err(error) => return Err(format!("dedicated_ip_hours sweep failed: {error}")),
    }

    match sweep_tenant_cost_quantities(pool, day, recorded_at).await {
        Ok((storage, bandwidth)) => {
            result.storage_gb_hours = storage;
            result.bandwidth_gb = bandwidth;
        }
        Err(error) if is_missing_table(&error) => {
            result.skipped_sources.push("tenant_costs".into());
        }
        Err(error) => return Err(format!("tenant_costs sweep failed: {error}")),
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Reconciliation: reserved vs delivered per tenant per day
// ---------------------------------------------------------------------------

/// Summary of one reconciliation run.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ReconciliationSummary {
    pub day: String,
    pub tenants_compared: i64,
    pub reports_written: i64,
    pub overage_candidates: i64,
    pub skipped_sources: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReconUsageRow {
    tenant_id: String,
    reserved: Option<i64>,
    delivered: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReconBounceRow {
    tenant_id: String,
    bounced: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReconComplaintRow {
    tenant_id: String,
    complained: Option<i64>,
}

/// Thresholds for flagging a tenant-day as an overage candidate
/// (reserved ≫ delivered with no bounce explanation). Absolute slack
/// absorbs small pipelines still in flight; the relative slack catches
/// systematic leaks at any scale.
pub const RECON_ABSOLUTE_SLACK: i64 = 25;
pub const RECON_RELATIVE_SLACK_PERCENT: i64 = 5;

/// Classify one tenant-day comparison. Pure — unit-tested.
///
/// `unaccounted` = reserved − delivered − bounced (may be negative when
/// delivered/bounced reporting overshoots; only positive gaps can flag).
/// A day is an overage candidate when the unaccounted volume exceeds BOTH
/// the absolute slack and the relative slack — i.e. reserved ≫ delivered
/// with no bounce explanation means either a quota leak or a delivery
/// failure, and both need a human.
pub fn classify_reconciliation(reserved: i64, delivered: i64, bounced: i64) -> (i64, bool) {
    let unaccounted = reserved - delivered - bounced;
    let relative_slack = reserved.saturating_mul(RECON_RELATIVE_SLACK_PERCENT) / 100;
    let threshold = RECON_ABSOLUTE_SLACK.max(relative_slack);
    let candidate = reserved > 0 && unaccounted > threshold;
    (unaccounted, candidate)
}

/// Compare metered `emails_sent` reservations against derived
/// `emails_delivered` (plus bounce/complaint outcomes) for the last closed
/// day and write one `billing_reconciliation_reports` row per tenant
/// (idempotent on `(tenant_id, period_start, period_end)`).
///
/// Report-only by design: systematically reserved≫delivered means either
/// quota leaks or delivery failures — a human decides, this job never
/// refunds. Bounced/complaint sends are reported distinctly so
/// reserved-but-bounced delivery failures are not mistaken for leaks.
pub async fn reconcile_daily_deliveries(
    pool: &PgPool,
    now: DateTime<Utc>,
) -> Result<ReconciliationSummary, String> {
    let day = sweep_target_day(now);
    let (day_start, day_end) = day_bounds(day);
    let mut summary = ReconciliationSummary {
        day: day.to_string(),
        ..ReconciliationSummary::default()
    };

    // 1. Reserved vs delivered from the metering tables.
    let usage_rows: Vec<ReconUsageRow> = sqlx::query_as(
        r#"
        SELECT tenant_id,
               SUM(quantity) FILTER (WHERE event_type = 'emails_sent') AS reserved,
               SUM(quantity) FILTER (WHERE event_type = 'emails_delivered') AS delivered
        FROM metering_events
        WHERE timestamp >= $1 AND timestamp < $2
          AND event_type IN ('emails_sent', 'emails_delivered')
        GROUP BY tenant_id
        "#,
    )
    .bind(day_start)
    .bind(day_end)
    .fetch_all(pool)
    .await
    .map_err(|error| format!("reconciliation usage query failed: {error}"))?;

    // 2. Bounced sends for the day. bounce_analytics_daily (aggregated by
    //    the bounce pipeline) is preferred; when absent for the day, fall
    //    back to counting terminal-bounced queue rows.
    let bounced_by_tenant: HashMap<String, i64> =
        match collect_bounce_counts(pool, day).await {
            Ok(counts) => counts,
            Err(error) if is_missing_table(&error) => {
                summary.skipped_sources.push("bounce_analytics_daily".into());
                HashMap::new()
            }
            Err(error) => return Err(format!("bounce collection failed: {error}")),
        };

    // 3. Complaints (FBL) for the day — reported distinctly, NOT deducted
    //    from delivered (a complaint implies the message was delivered).
    let complained_by_tenant: HashMap<String, i64> =
        match collect_complaint_counts(pool, day_start, day_end).await {
            Ok(counts) => counts,
            Err(error) if is_missing_table(&error) => {
                summary.skipped_sources.push("complaints".into());
                HashMap::new()
            }
            Err(error) => return Err(format!("complaint collection failed: {error}")),
        };

    summary.tenants_compared = i64::try_from(usage_rows.len()).unwrap_or(i64::MAX);

    for row in usage_rows {
        let reserved = row.reserved.unwrap_or(0);
        let delivered = row.delivered.unwrap_or(0);
        let bounced = bounced_by_tenant.get(&row.tenant_id).copied().unwrap_or(0);
        let complained = complained_by_tenant
            .get(&row.tenant_id)
            .copied()
            .unwrap_or(0);
        let (unaccounted, candidate) = classify_reconciliation(reserved, delivered, bounced);

        let inserted = sqlx::query(
            r#"
            INSERT INTO billing_reconciliation_reports (
                id, tenant_id, period_start, period_end,
                reserved_emails, delivered_emails, bounced_emails, complained_emails,
                unaccounted_emails, overage_candidate, status, details, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'open', $11, NOW())
            ON CONFLICT (tenant_id, period_start, period_end) DO NOTHING
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&row.tenant_id)
        .bind(day)
        .bind(day + Duration::days(1))
        .bind(reserved)
        .bind(delivered)
        .bind(bounced)
        .bind(complained)
        .bind(unaccounted)
        .bind(candidate)
        .bind(json!({
            "reservedButBounced": bounced,
            "note": "reserved-but-bounced sends are delivery failures, not quota leaks",
        }))
        .execute(pool)
        .await
        .map_err(|error| format!("reconciliation report write failed: {error}"))?;

        if inserted.rows_affected() == 1 {
            summary.reports_written += 1;
            if candidate {
                summary.overage_candidates += 1;
            }
        }
    }

    Ok(summary)
}

async fn collect_bounce_counts(
    pool: &PgPool,
    day: NaiveDate,
) -> Result<HashMap<String, i64>, sqlx::Error> {
    // Aggregated bounce pipeline first (covers SES + self-hosted feeds).
    let aggregated: Vec<ReconBounceRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, SUM(total_bounces)::bigint AS bounced
        FROM bounce_analytics_daily
        WHERE date = $1 AND total_bounces > 0
        GROUP BY tenant_id
        "#,
    )
    .bind(day)
    .fetch_all(pool)
    .await?;

    let mut counts: HashMap<String, i64> = HashMap::new();
    for row in aggregated {
        counts.insert(row.tenant_id, row.bounced.unwrap_or(0));
    }

    if counts.is_empty() {
        // Fallback: terminal-bounced queue rows attributed by updated_at.
        let (day_start, day_end) = day_bounds(day);
        let rows: Vec<ReconBounceRow> = sqlx::query_as(
            r#"
            SELECT tenant_id::text AS tenant_id, COUNT(*)::bigint AS bounced
            FROM email_queue
            WHERE status = 'bounced'
              AND updated_at >= $1
              AND updated_at <  $2
              AND tenant_id IS NOT NULL
            GROUP BY tenant_id
            "#,
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(pool)
        .await?;
        for row in rows {
            counts.insert(row.tenant_id, row.bounced.unwrap_or(0));
        }
    }

    Ok(counts)
}

async fn collect_complaint_counts(
    pool: &PgPool,
    day_start: DateTime<Utc>,
    day_end: DateTime<Utc>,
) -> Result<HashMap<String, i64>, sqlx::Error> {
    // `complaints` (069) first; `self_hosted_complaints` (021) as fallback.
    let rows: Vec<ReconComplaintRow> = match sqlx::query_as(
        r#"
        SELECT tenant_id, COUNT(*)::bigint AS complained
        FROM complaints
        WHERE created_at >= $1 AND created_at < $2
        GROUP BY tenant_id
        "#,
    )
    .bind(day_start)
    .bind(day_end)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_missing_table(&error) => {
            sqlx::query_as(
                r#"
                SELECT tenant_id::text AS tenant_id, COUNT(*)::bigint AS complained
                FROM self_hosted_complaints
                WHERE received_at >= $1 AND received_at < $2
                GROUP BY tenant_id
                "#,
            )
            .bind(day_start)
            .bind(day_end)
            .fetch_all(pool)
            .await?
        }
        Err(error) => return Err(error),
    };

    Ok(rows
        .into_iter()
        .map(|row| (row.tenant_id, row.complained.unwrap_or(0)))
        .collect())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_target_day_is_previous_utc_day() {
        let now = DateTime::parse_from_rfc3339("2026-08-21T10:15:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(sweep_target_day(now).to_string(), "2026-08-20");

        // Midnight edge: the 1st targets the last day of the previous month.
        let midnight = DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(sweep_target_day(midnight).to_string(), "2026-02-28");
    }

    #[test]
    fn derived_event_id_is_deterministic_and_distinct_per_component() {
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let a = derived_event_id("tenant-1", "emails_delivered", day, SOURCE_EMAIL_DELIVERY);
        let b = derived_event_id("tenant-1", "emails_delivered", day, SOURCE_EMAIL_DELIVERY);
        assert_eq!(a, b, "same inputs must derive the same id");

        assert_ne!(
            a,
            derived_event_id("tenant-2", "emails_delivered", day, SOURCE_EMAIL_DELIVERY),
            "tenant is part of the id"
        );
        assert_ne!(
            a,
            derived_event_id("tenant-1", "webhooks_delivered", day, SOURCE_EMAIL_DELIVERY),
            "event type is part of the id"
        );
        assert_ne!(
            a,
            derived_event_id(
                "tenant-1",
                "emails_delivered",
                day + Duration::days(1),
                SOURCE_EMAIL_DELIVERY
            ),
            "day is part of the id"
        );
        assert_ne!(
            a,
            derived_event_id("tenant-1", "emails_delivered", day, SOURCE_WEBHOOK_EVENTS),
            "source is part of the id"
        );
    }

    #[test]
    fn emails_delivered_has_a_single_marker_source_across_derivation_paths() {
        // The combined queue+delivery-log derivation and the queue-only
        // fallback MUST share one marker source: distinct sources would let
        // a re-run after a schema change double-record the same tenant/day.
        assert_eq!(SOURCE_EMAIL_DELIVERY, "email_delivery_sweep");
        // …and every other source family is distinct.
        assert_ne!(SOURCE_EMAIL_DELIVERY, SOURCE_WEBHOOK_EVENTS);
        assert_ne!(SOURCE_EMAIL_DELIVERY, SOURCE_DEDICATED_IPS);
        assert_ne!(SOURCE_EMAIL_DELIVERY, SOURCE_TENANT_COSTS);
    }

    #[test]
    fn classify_reconciliation_balanced_day_is_not_candidate() {
        let (unaccounted, candidate) = classify_reconciliation(1_000, 990, 10);
        assert_eq!(unaccounted, 0);
        assert!(!candidate);
    }

    #[test]
    fn classify_reconciliation_small_slack_is_absorbed() {
        // 5 missing out of 10 000 is within both slacks.
        let (unaccounted, candidate) = classify_reconciliation(10_000, 9_995, 0);
        assert_eq!(unaccounted, 5);
        assert!(!candidate);
    }

    #[test]
    fn classify_reconciliation_systematic_gap_flags_candidate() {
        // Half the reservations never delivered and no bounce explanation.
        let (unaccounted, candidate) = classify_reconciliation(10_000, 5_000, 0);
        assert_eq!(unaccounted, 5_000);
        assert!(
            candidate,
            "reserved >> delivered must flag an overage candidate"
        );
    }

    #[test]
    fn classify_reconciliation_bounced_sends_explain_the_gap() {
        // The reserved-but-bounced distinction: a day where every
        // unaccounted send is explained by bounces is NOT a leak.
        let (unaccounted, candidate) = classify_reconciliation(10_000, 4_000, 6_000);
        assert_eq!(unaccounted, 0);
        assert!(!candidate);
    }

    #[test]
    fn classify_reconciliation_relative_slack_scales() {
        // 100 unaccounted of 1 000 000 (0.01 %) — within relative slack.
        let (_, candidate_small) = classify_reconciliation(1_000_000, 999_900, 0);
        assert!(!candidate_small);

        // 60 000 unaccounted of 1 000 000 (6 %) — beyond 5 % relative slack.
        let (unaccounted, candidate_large) = classify_reconciliation(1_000_000, 940_000, 0);
        assert_eq!(unaccounted, 60_000);
        assert!(candidate_large);
    }

    #[test]
    fn classify_reconciliation_zero_reserved_never_flags() {
        let (unaccounted, candidate) = classify_reconciliation(0, 0, 0);
        assert_eq!(unaccounted, 0);
        assert!(!candidate);
    }

    #[test]
    fn classify_reconciliation_negative_unaccounted_does_not_flag() {
        // Derived delivered overshooting reserved (late markers) must not
        // produce a candidate.
        let (unaccounted, candidate) = classify_reconciliation(100, 500, 0);
        assert_eq!(unaccounted, -400);
        assert!(!candidate);
    }

    #[test]
    fn classify_reconciliation_absolute_floor_applies_to_small_tenants() {
        // 20 unaccounted of 30 reserved is > 5 % but within the absolute
        // floor of 25 — small tenants are not flagged for in-flight sends.
        let (_, candidate) = classify_reconciliation(30, 10, 0);
        assert!(!candidate, "absolute slack floor must apply");

        // 26 unaccounted exceeds the floor and 5 % of 30.
        let (_, candidate) = classify_reconciliation(30, 4, 0);
        assert!(candidate);
    }

    #[test]
    fn ingest_batch_limit_is_bounded() {
        assert_eq!(INGEST_BATCH_LIMIT, 1_000);
    }

    #[test]
    fn ingest_event_deserializes_camel_case() {
        let body = serde_json::json!({
            "tenantId": "tenant-1",
            "eventType": "api_calls",
            "quantity": 42,
            "eventId": "00000000-0000-5000-8000-000000000000",
            "metadata": { "path": "/v1/messages" }
        });
        let event: IngestEvent = serde_json::from_value(body).expect("deserialize");
        assert_eq!(event.tenant_id, "tenant-1");
        assert_eq!(
            crate::usage::meter_event_type_str(event.event_type),
            "api_calls"
        );
        assert_eq!(event.quantity, 42);
        assert!(event.event_id.is_some());
    }

    #[test]
    fn ingest_event_defaults_quantity_to_one() {
        let event: IngestEvent = serde_json::from_value(serde_json::json!({
            "tenantId": "t",
            "eventType": "api_calls"
        }))
        .expect("deserialize");
        assert_eq!(event.quantity, 1);
    }

    #[test]
    fn ingest_event_rejects_unknown_event_types() {
        let body = serde_json::json!({ "tenantId": "t", "eventType": "nonsense" });
        assert!(serde_json::from_value::<IngestEvent>(body).is_err());
    }

    #[test]
    fn ingest_event_rejects_unknown_fields() {
        let body = serde_json::json!({
            "tenantId": "t",
            "eventType": "api_calls",
            "surprise": true
        });
        assert!(serde_json::from_value::<IngestEvent>(body).is_err());
    }
}
