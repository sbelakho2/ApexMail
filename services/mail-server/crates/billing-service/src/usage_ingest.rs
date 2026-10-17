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
//! Fractional quantities (GB) are recorded as whole units with a
//! deterministic cross-day carry: each sweep meters
//! `FLOOR(cumulative source total through the day) − already-metered whole
//! units from this source` (see [`sweep_tenant_cost_quantities`]), so
//! sub-unit usage like 0.4 GB/day accumulates instead of being rounded away
//! — while every stored quantity stays a whole unit (consumers such as the
//! `/usage` report display `SUM(quantity)` verbatim). `dedicated_ip_hours`
//! keeps the per-day half-up SQL `ROUND` (lifecycle-interval overlap in
//! hours).

use std::collections::HashMap;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder};
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
    let start = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let end = (day + Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();
    (start, end)
}

/// Rows per multi-row INSERT.
///
/// PostgreSQL rejects any statement carrying more than 65,535 bound
/// parameters (`42P08`/protocol error). The widest insert in this module binds
/// 12 columns per row (reconciliation reports), so 5,000 rows <= 60,000 binds
/// stays below the ceiling while keeping the statement count low.
const MULTI_ROW_INSERT_CHUNK_ROWS: usize = 5_000;

/// Record one derived daily aggregate per tenant, idempotently, for a whole
/// source sweep in a bounded number of statements (P3: the pre-fix path ran
/// one transaction + marker + event + audit per tenant row).
///
/// Ordering and semantics are preserved:
/// 1. Multi-row marker INSERTs (one per [`MULTI_ROW_INSERT_CHUNK_ROWS`] chunk)
///    are the idempotency gate; only rows the statements actually inserted
///    are returned (a replay gets none).
/// 2. Multi-row metering-event INSERTs (one per chunk) carry every newly-gated
///    tenant with a positive quantity (deterministic ids; `ON CONFLICT` is the
///    belt to the marker's braces).
/// 3. One audit entry per newly-metered aggregate, appended INSIDE the same
///    transaction — the audit trail is a global hash chain and cannot be
///    set-based without changing its ordering contract, so this is the only
///    remaining per-row statement (2: chain-head UPDATE + INSERT).
///
/// Returns the number of newly recorded non-zero aggregates (the previous
/// per-row return contract).
async fn record_tenant_counts(
    pool: &PgPool,
    event_type: &str,
    day: NaiveDate,
    source: &str,
    rows: Vec<TenantCountRow>,
    recorded_at: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    record_tenant_counts_chunked(
        pool,
        event_type,
        day,
        source,
        rows,
        recorded_at,
        MULTI_ROW_INSERT_CHUNK_ROWS,
    )
    .await
}

/// [`record_tenant_counts`] with an explicit chunk size (tests shrink it to
/// exercise the chunk boundary on a small fixture; production uses
/// [`MULTI_ROW_INSERT_CHUNK_ROWS`]).
async fn record_tenant_counts_chunked(
    pool: &PgPool,
    event_type: &str,
    day: NaiveDate,
    source: &str,
    rows: Vec<TenantCountRow>,
    recorded_at: DateTime<Utc>,
    chunk_rows: usize,
) -> Result<i64, sqlx::Error> {
    if rows.is_empty() {
        return Ok(0);
    }
    let chunk_rows = chunk_rows.max(1);

    let mut tx = pool.begin().await?;

    // 1. Markers first — UNIQUE(tenant, event_type, day, source) makes this
    //    the idempotency gate for every aggregate. Zero-quantity days still
    //    get a marker so the sweep does not re-derive emptiness. Chunked: a
    //    source sweep can carry one row per tenant and blow the 65,535-bind
    //    statement ceiling in one unbounded multi-row INSERT.
    let mut fresh: Vec<(String, i64)> = Vec::with_capacity(rows.len());
    for chunk in rows.chunks(chunk_rows) {
        #[cfg(test)]
        crate::test_support::query_count::bump("derived.db.markers");
        let mut marker_builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO metering_daily_markers (tenant_id, event_type, day, source, quantity) ",
        );
        marker_builder.push_values(chunk, |mut values, row| {
            values
                .push_bind(row.tenant_id.clone())
                .push_bind(event_type)
                .push_bind(day)
                .push_bind(source)
                .push_bind(row.quantity.max(0));
        });
        marker_builder.push(
            " ON CONFLICT (tenant_id, event_type, day, source) DO NOTHING
              RETURNING tenant_id, quantity",
        );
        fresh.extend(
            marker_builder
                .build_query_as::<(String, i64)>()
                .fetch_all(&mut *tx)
                .await?,
        );
    }

    let positive: Vec<(String, i64)> = fresh
        .into_iter()
        .filter(|(_, quantity)| *quantity > 0)
        .collect();

    if !positive.is_empty() {
        // 2. Multi-row metering insert, one statement per chunk. The table is
        //    RANGE-partitioned by "timestamp" with PRIMARY KEY (id, timestamp):
        //    the bare (id) arbiter raises 42P10.
        let metadata = serde_json::json!({
            "source": source,
            "derived": true,
            "day": day.to_string(),
        });
        for chunk in positive.chunks(chunk_rows) {
            #[cfg(test)]
            crate::test_support::query_count::bump("derived.db.events");
            let mut event_builder = QueryBuilder::<Postgres>::new(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata) ",
            );
            event_builder.push_values(chunk, |mut values, (tenant_id, quantity)| {
                values
                    .push_bind(derived_event_id(tenant_id, event_type, day, source))
                    .push_bind(tenant_id.clone())
                    .push_bind(event_type)
                    .push_bind(*quantity)
                    .push_bind(recorded_at)
                    .push_bind(metadata.clone());
            });
            event_builder.push(" ON CONFLICT (id, \"timestamp\") DO NOTHING");
            event_builder.build().execute(&mut *tx).await?;
        }

        // 3. Immutable audit records (one per aggregate; chain order).
        for (tenant_id, quantity) in &positive {
            append_audit_log(
                &mut tx,
                tenant_id,
                "billing.metering_derived_aggregate_recorded",
                "metering_event",
                Some(&derived_event_id(tenant_id, event_type, day, source).to_string()),
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
        }
    }

    tx.commit().await?;
    Ok(i64::try_from(positive.len()).unwrap_or(i64::MAX))
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
/// migration 022).
///
/// Fix F9 — sub-unit accumulation. Rounding each day independently
/// (`ROUND(storage_gb * 24)`, `ROUND(bandwidth_gb)`) discarded fractional
/// usage forever: a tenant burning 0.4 GB/day metered 0 — every day,
/// forever. Consumers were traced before choosing the mechanism: nothing
/// multiplies these quantities back (invoice PAYG pricing reads
/// `tenant_costs`' cost columns, enterprise contracts sum `emails_sent`,
/// the daily reconciliation reads `emails_sent`/`emails_delivered`), but
/// the `/usage` report surfaces `SUM(quantity)` per event type verbatim to
/// users, so metering in milli-units would silently change the displayed
/// unit. The remainder is therefore accumulated deterministically, keyed by
/// (tenant, resource) across days, WITHOUT new state: each sweep meters
/// `FLOOR(cumulative source total through the day) − already-metered whole
/// units from this source` (clamped at ≥ 0). The daily deltas telescope to
/// `floor(total)` exactly, so 0.4 GB/day meters 0, 0, 1, 0, 1, ... instead
/// of all zeroes. All arithmetic is SQL-side DECIMAL → BIGINT; no Rust
/// float path.
async fn sweep_tenant_cost_quantities(
    pool: &PgPool,
    day: NaiveDate,
    recorded_at: DateTime<Utc>,
) -> Result<(i64, i64), sqlx::Error> {
    let storage_rows: Vec<TenantCountRow> = sqlx::query_as(
        r#"
        WITH active_today AS (
            SELECT DISTINCT tenant_id
            FROM tenant_costs
            WHERE recorded_at = $1
              AND (storage_gb > 0 OR bandwidth_gb > 0)
        ),
        cumulative AS (
            SELECT tenant_id, FLOOR(SUM(storage_gb) * 24)::bigint AS units
            FROM tenant_costs
            WHERE recorded_at <= $1
              AND storage_gb > 0
            GROUP BY tenant_id
        ),
        metered AS (
            SELECT tenant_id, COALESCE(SUM(quantity), 0)::bigint AS metered
            FROM metering_events
            WHERE event_type = 'storage_gb_hours'
              AND metadata->>'source' = $2
            GROUP BY tenant_id
        )
        SELECT a.tenant_id,
               GREATEST(c.units - COALESCE(m.metered, 0), 0)::bigint AS quantity
        FROM active_today a
        JOIN cumulative c ON c.tenant_id = a.tenant_id
        LEFT JOIN metered m ON m.tenant_id = a.tenant_id
        "#,
    )
    .bind(day)
    .bind(SOURCE_TENANT_COSTS)
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
        WITH active_today AS (
            SELECT DISTINCT tenant_id
            FROM tenant_costs
            WHERE recorded_at = $1
              AND (storage_gb > 0 OR bandwidth_gb > 0)
        ),
        cumulative AS (
            SELECT tenant_id, FLOOR(SUM(bandwidth_gb))::bigint AS units
            FROM tenant_costs
            WHERE recorded_at <= $1
              AND bandwidth_gb > 0
            GROUP BY tenant_id
        ),
        metered AS (
            SELECT tenant_id, COALESCE(SUM(quantity), 0)::bigint AS metered
            FROM metering_events
            WHERE event_type = 'bandwidth_gb'
              AND metadata->>'source' = $2
            GROUP BY tenant_id
        )
        SELECT a.tenant_id,
               GREATEST(c.units - COALESCE(m.metered, 0), 0)::bigint AS quantity
        FROM active_today a
        JOIN cumulative c ON c.tenant_id = a.tenant_id
        LEFT JOIN metered m ON m.tenant_id = a.tenant_id
        "#,
    )
    .bind(day)
    .bind(SOURCE_TENANT_COSTS)
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
    reconcile_daily_deliveries_chunked(pool, now, MULTI_ROW_INSERT_CHUNK_ROWS).await
}

/// [`reconcile_daily_deliveries`] with an explicit report-insert chunk size
/// (tests shrink it to cross the chunk boundary; production uses
/// [`MULTI_ROW_INSERT_CHUNK_ROWS`]).
async fn reconcile_daily_deliveries_chunked(
    pool: &PgPool,
    now: DateTime<Utc>,
    chunk_rows: usize,
) -> Result<ReconciliationSummary, String> {
    let chunk_rows = chunk_rows.max(1);
    let day = sweep_target_day(now);
    let (day_start, day_end) = day_bounds(day);
    let mut summary = ReconciliationSummary {
        day: day.to_string(),
        ..ReconciliationSummary::default()
    };

    // 1. Reserved vs delivered from the metering tables. SUM(bigint) yields
    //    NUMERIC in PostgreSQL, which cannot decode into Option<i64> — the
    //    reconciliation sweep failed on every day that actually had usage.
    //    Cast each aggregate back to bigint.
    #[cfg(test)]
    crate::test_support::query_count::bump("recon.db.usage");
    let usage_rows: Vec<ReconUsageRow> = sqlx::query_as(
        r#"
        SELECT tenant_id,
               SUM(quantity) FILTER (WHERE event_type = 'emails_sent')::bigint AS reserved,
               SUM(quantity) FILTER (WHERE event_type = 'emails_delivered')::bigint AS delivered
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
    let bounced_by_tenant: HashMap<String, i64> = match collect_bounce_counts(pool, day).await {
        Ok(counts) => counts,
        Err(error) if is_missing_table(&error) => {
            summary
                .skipped_sources
                .push("bounce_analytics_daily".into());
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

    // P3 fix 2 — the report writes are multi-row INSERTs (per-row INSERT was
    // the last O(tenants) statement in this sweep), one statement per
    // `MULTI_ROW_INSERT_CHUNK_ROWS` chunk so an unbounded tenant count cannot
    // exceed PostgreSQL's 65,535 bound-parameter ceiling. `ON CONFLICT DO
    // NOTHING RETURNING` preserves the exact accounting: only rows this run
    // actually inserted count toward `reports_written`, and only those can
    // raise `overage_candidates`.
    struct ReconciliationReportRow {
        tenant_id: String,
        reserved: i64,
        delivered: i64,
        bounced: i64,
        complained: i64,
        unaccounted: i64,
        candidate: bool,
        details: serde_json::Value,
    }
    let mut reports: Vec<ReconciliationReportRow> = Vec::with_capacity(usage_rows.len());
    for row in usage_rows {
        let reserved = row.reserved.unwrap_or(0);
        let delivered = row.delivered.unwrap_or(0);
        let bounced = bounced_by_tenant.get(&row.tenant_id).copied().unwrap_or(0);
        let complained = complained_by_tenant
            .get(&row.tenant_id)
            .copied()
            .unwrap_or(0);
        let (unaccounted, candidate) = classify_reconciliation(reserved, delivered, bounced);
        reports.push(ReconciliationReportRow {
            tenant_id: row.tenant_id,
            reserved,
            delivered,
            bounced,
            complained,
            unaccounted,
            candidate,
            details: json!({
                "reservedButBounced": bounced,
                "note": "reserved-but-bounced sends are delivery failures, not quota leaks",
            }),
        });
    }

    if !reports.is_empty() {
        for chunk in reports.chunks(chunk_rows) {
            #[cfg(test)]
            crate::test_support::query_count::bump("recon.db.write");
            let mut builder = QueryBuilder::<Postgres>::new(
                "INSERT INTO billing_reconciliation_reports (
                    id, tenant_id, period_start, period_end,
                    reserved_emails, delivered_emails, bounced_emails, complained_emails,
                    unaccounted_emails, overage_candidate, status, details, created_at
                 ) ",
            );
            builder.push_values(chunk, |mut values, report| {
                values
                    .push_bind(Uuid::new_v4())
                    .push_bind(report.tenant_id.clone())
                    .push_bind(day)
                    .push_bind(day + Duration::days(1))
                    .push_bind(report.reserved)
                    .push_bind(report.delivered)
                    .push_bind(report.bounced)
                    .push_bind(report.complained)
                    .push_bind(report.unaccounted)
                    .push_bind(report.candidate)
                    .push_bind("open")
                    .push_bind(report.details.clone())
                    .push("NOW()");
            });
            builder.push(
                " ON CONFLICT (tenant_id, period_start, period_end) DO NOTHING
                  RETURNING overage_candidate",
            );
            let inserted: Vec<(bool,)> = builder
                .build_query_as()
                .fetch_all(pool)
                .await
                .map_err(|error| format!("reconciliation report write failed: {error}"))?;
            summary.reports_written += i64::try_from(inserted.len()).unwrap_or(i64::MAX);
            summary.overage_candidates +=
                i64::try_from(inserted.iter().filter(|(candidate,)| *candidate).count())
                    .unwrap_or(i64::MAX);
        }
    }

    Ok(summary)
}

async fn collect_bounce_counts(
    pool: &PgPool,
    day: NaiveDate,
) -> Result<HashMap<String, i64>, sqlx::Error> {
    // Aggregated bounce pipeline first (covers SES + self-hosted feeds).
    #[cfg(test)]
    crate::test_support::query_count::bump("recon.db.bounce");
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
        #[cfg(test)]
        crate::test_support::query_count::bump("recon.db.bounce");
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
    #[cfg(test)]
    crate::test_support::query_count::bump("recon.db.complaint");
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

    // ─── Redis/DB-backed sweep and reconciliation paths ───────────
    //
    // Fault injection: each test clones its own canonical database, so
    // renaming a table deterministically produces the production 42P01
    // (missing relation) classification without touching any other test.

    /// Unique per-run tenant ids: derived markers, metering rows and queue
    /// rows persist, so a repeated invocation of a test must never collide
    /// with a previous run's data.
    fn unique_tenant(tag: &str) -> String {
        let keep = 26usize.saturating_sub(tag.len() + 1).min(12);
        format!(
            "{tag}_{}",
            &Uuid::new_v4().simple().to_string()[..keep.max(4)]
        )
    }

    async fn provision_env(tag: &str) -> crate::test_support::TestEnv {
        crate::test_support::provision(tag)
            .await
            .expect("TEST_DATABASE_URL/redis must be configured for this suite")
    }

    async fn rename_table(pool: &sqlx::PgPool, from: &str, to: &str) {
        sqlx::query(&format!(r#"ALTER TABLE "{from}" RENAME TO "{to}""#))
            .execute(pool)
            .await
            .expect("rename table");
    }

    fn yesterday(now: DateTime<Utc>) -> NaiveDate {
        sweep_target_day(now)
    }

    async fn seed_sent_queue_row(pool: &sqlx::PgPool, tenant_id: &str, day: NaiveDate) {
        sqlx::query(
            r#"
            INSERT INTO email_queue (tenant_id, from_address, to_addresses, subject, status, sent_at, created_at, updated_at)
            VALUES ($1, 'noreply@example.com', ARRAY['rcpt@example.com'], 'cov', 'sent',
                    $2::timestamptz, $2::timestamptz, $2::timestamptz)
            "#,
        )
        .bind(tenant_id)
        .bind(day.and_hms_opt(12, 0, 0).unwrap().and_utc())
        .execute(pool)
        .await
        .expect("seed sent queue row");
    }

    #[tokio::test]
    async fn derived_aggregate_zero_quantity_is_marker_only_and_never_double_records() {
        let owned = provision_env("ingest_zero_marker").await;
        let pool = &owned.pool;
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let now = Utc::now();
        let t_zero = unique_tenant("ing_zero_t");

        // Fresh non-zero aggregate: recorded with event + audit.
        let fresh = record_tenant_counts(
            pool,
            "emails_delivered",
            day,
            SOURCE_EMAIL_DELIVERY,
            vec![TenantCountRow {
                tenant_id: t_zero.clone(),
                quantity: 5,
            }],
            now,
        )
        .await
        .expect("fresh aggregate");
        assert_eq!(fresh, 1);

        // Zero quantity: a marker-only row, no metering event.
        let marker_only = record_tenant_counts(
            pool,
            "emails_delivered",
            day,
            SOURCE_WEBHOOK_EVENTS,
            vec![TenantCountRow {
                tenant_id: t_zero.clone(),
                quantity: 0,
            }],
            now,
        )
        .await
        .expect("marker-only aggregate");
        assert_eq!(marker_only, 0, "zero quantity records a marker only");
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1 AND event_type = 'webhooks_delivered'",
        )
        .bind(&t_zero)
        .fetch_one(pool)
        .await
        .expect("count");
        assert_eq!(events, 0, "marker-only rows never meter");
        let markers: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM metering_daily_markers WHERE tenant_id = $1")
                .bind(&t_zero)
                .fetch_one(pool)
                .await
                .expect("markers");
        assert_eq!(markers, 2, "both sources got their marker");

        // Duplicate marker: the idempotency gate reports no new aggregate.
        let duplicate = record_tenant_counts(
            pool,
            "emails_delivered",
            day,
            SOURCE_EMAIL_DELIVERY,
            vec![TenantCountRow {
                tenant_id: t_zero.clone(),
                quantity: 5,
            }],
            now,
        )
        .await
        .expect("duplicate aggregate");
        assert_eq!(duplicate, 0, "the marker gate makes re-runs idempotent");

        // Exactly ONE audit entry for the ONE newly metered aggregate.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'billing.metering_derived_aggregate_recorded'",
        )
        .bind(&t_zero)
        .fetch_one(pool)
        .await
        .expect("audit rows");
        assert_eq!(audited, 1);

        owned.finish().await;
    }

    // P3 item 7 — the derived-aggregate writer was per-tenant (one
    // transaction + marker + event + audit per row). Markers and events are
    // now ONE multi-row statement per source; only the hash-chained audit
    // append stays per newly metered row. Three tenants must cost ONE marker
    // statement and ONE event statement, not three of each.
    #[tokio::test]
    async fn derived_aggregates_write_once_per_source_not_per_tenant() {
        use crate::test_support::query_count;

        let owned = provision_env("ingest_derived_batch").await;
        let pool = &owned.pool;
        let day = yesterday(Utc::now());
        let mut seeded = Vec::new();
        for suffix in ["a", "b", "c"] {
            let tenant = unique_tenant(&format!("ing_derived_batch_{suffix}"));
            crate::test_support::seed_tenant(pool, &tenant, "growth").await;
            seed_sent_queue_row(pool, &tenant, day).await;
            seeded.push(tenant);
        }

        query_count::reset();
        let result = sweep_derived_usage(pool, Utc::now())
            .await
            .expect("derived sweep");
        assert_eq!(result.emails_delivered, 3, "all three tenants derived");
        assert_eq!(
            query_count::count("derived.db.markers"),
            1,
            "one marker INSERT for the whole source, not per tenant"
        );
        assert_eq!(
            query_count::count("derived.db.events"),
            1,
            "one event INSERT for the whole source, not per tenant"
        );

        let metered: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM metering_events
              WHERE tenant_id = ANY($1) AND event_type = 'emails_delivered'",
        )
        .bind(&seeded)
        .fetch_one(pool)
        .await
        .expect("metering events");
        assert_eq!(metered, 3);
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
              WHERE tenant_id = ANY($1) AND action = 'billing.metering_derived_aggregate_recorded'",
        )
        .bind(&seeded)
        .fetch_one(pool)
        .await
        .expect("audit entries");
        assert_eq!(audited, 3, "one audit entry per metered aggregate");

        // Replay: markers gate everything; no new markers or events.
        query_count::reset();
        let replay = sweep_derived_usage(pool, Utc::now())
            .await
            .expect("replay sweep");
        assert_eq!(replay.emails_delivered, 0);
        assert_eq!(query_count::count("derived.db.markers"), 1);
        assert_eq!(
            query_count::count("derived.db.events"),
            0,
            "a replay inserts no events"
        );

        owned.finish().await;
    }

    /// F-audit P2 (PostgreSQL 65,535-parameter ceiling): the derived-aggregate
    /// writer must split an oversized row set into multiple statements. The
    /// chunk size is shrunk here (production uses the pinned 5,000-row
    /// constant) so a 5-row fixture crosses the boundary: 5 rows / 2 per
    /// statement = 3 marker INSERTs and 3 metering-event INSERTs, with every
    /// row persisted.
    ///
    /// Fail-before: the unbounded single `push_values` issues exactly ONE
    /// statement for all 5 rows.
    #[tokio::test]
    async fn derived_aggregate_writes_chunk_above_the_parameter_boundary() {
        use crate::test_support::query_count;

        let owned = provision_env("ingest_derived_chunk_boundary").await;
        let pool = &owned.pool;
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let rows: Vec<TenantCountRow> = (0..5)
            .map(|index| TenantCountRow {
                tenant_id: unique_tenant(&format!("ing_derived_chunk_{index}")),
                quantity: 2,
            })
            .collect();
        let tenants: Vec<String> = rows.iter().map(|row| row.tenant_id.clone()).collect();

        query_count::reset();
        let recorded = record_tenant_counts_chunked(
            pool,
            "emails_delivered",
            day,
            SOURCE_EMAIL_DELIVERY,
            rows,
            Utc::now(),
            2,
        )
        .await
        .expect("chunked aggregate write");
        assert_eq!(recorded, 5, "every row is still recorded");
        assert_eq!(
            query_count::count("derived.db.markers"),
            3,
            "5 rows at 2 per chunk = 3 marker statements"
        );
        assert_eq!(
            query_count::count("derived.db.events"),
            3,
            "5 rows at 2 per chunk = 3 metering-event statements"
        );

        let markers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM metering_daily_markers \
             WHERE tenant_id = ANY($1) AND event_type = 'emails_delivered' AND day = $2",
        )
        .bind(&tenants)
        .bind(day)
        .fetch_one(pool)
        .await
        .expect("marker count");
        assert_eq!(markers, 5, "all marker rows persist across chunks");
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM metering_events \
             WHERE tenant_id = ANY($1) AND event_type = 'emails_delivered'",
        )
        .bind(&tenants)
        .fetch_one(pool)
        .await
        .expect("event count");
        assert_eq!(events, 5, "all metering events persist across chunks");

        // The production chunk size stays inside the bind ceiling for the
        // widest statement in this module (12 binds/row).
        const {
            assert!(MULTI_ROW_INSERT_CHUNK_ROWS * 12 <= 65_535);
        }

        owned.finish().await;
    }

    /// F-audit P2 (PostgreSQL 65,535-parameter ceiling): the reconciliation
    /// report writer chunks its multi-row INSERT. With a shrunk chunk of 2,
    /// five tenant-day reports cost 3 statements (not 1 unbounded, not 5
    /// per-row) and every report row persists.
    ///
    /// Fail-before: the unbounded single `push_values` issues exactly ONE
    /// statement.
    #[tokio::test]
    async fn reconciliation_reports_chunk_above_the_parameter_boundary() {
        use crate::test_support::query_count;

        let owned = provision_env("ingest_recon_chunk_boundary").await;
        let pool = &owned.pool;
        let day = yesterday(Utc::now());
        let (day_start, _day_end) = day_bounds(day);
        let mut tenants = Vec::new();
        for index in 0..5 {
            let tenant = unique_tenant(&format!("ing_recon_chunk_{index}"));
            crate::test_support::seed_tenant(pool, &tenant, "growth").await;
            for (event_type, quantity) in [("emails_sent", 100), ("emails_delivered", 10)] {
                sqlx::query(
                    r#"
                    INSERT INTO metering_events (id, tenant_id, event_type, quantity, "timestamp", metadata)
                    VALUES ($1, $2, $3, $4, $5, '{}')
                    "#,
                )
                .bind(Uuid::new_v4())
                .bind(&tenant)
                .bind(event_type)
                .bind(quantity)
                .bind(day_start + chrono::Duration::hours(5))
                .execute(pool)
                .await
                .expect("seed metering");
            }
            tenants.push(tenant);
        }

        query_count::reset();
        let summary = reconcile_daily_deliveries_chunked(pool, Utc::now(), 2)
            .await
            .expect("chunked reconciliation");
        assert_eq!(summary.tenants_compared, 5);
        assert_eq!(summary.reports_written, 5, "all reports written");
        assert_eq!(
            query_count::count("recon.db.write"),
            3,
            "5 reports at 2 per chunk = 3 report statements"
        );

        let persisted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_reconciliation_reports WHERE tenant_id = ANY($1)",
        )
        .bind(&tenants)
        .fetch_one(pool)
        .await
        .expect("report count");
        assert_eq!(persisted, 5, "all report rows persist across chunks");

        // The ON CONFLICT idempotency still holds per chunk on a replay.
        let replay = reconcile_daily_deliveries_chunked(pool, Utc::now(), 2)
            .await
            .expect("chunked replay");
        assert_eq!(replay.reports_written, 0, "replay inserts nothing new");

        owned.finish().await;
    }

    #[tokio::test]
    async fn sweep_skips_sources_whose_backing_tables_are_missing() {
        let owned = provision_env("ingest_sweep_skip").await;
        let pool = &owned.pool;
        rename_table(pool, "email_queue", "email_queue_gone").await;
        rename_table(pool, "webhook_events", "webhook_events_gone").await;
        rename_table(pool, "dedicated_ips", "dedicated_ips_gone").await;
        rename_table(pool, "tenant_costs", "tenant_costs_gone").await;

        let now = Utc::now();
        let result = sweep_derived_usage(pool, now).await.expect("sweep runs");
        let mut skipped = result.skipped_sources.clone();
        skipped.sort();
        assert_eq!(
            skipped,
            vec![
                "dedicated_ips".to_string(),
                "email_queue".to_string(),
                "tenant_costs".to_string(),
                "webhook_events".to_string(),
            ]
        );
        assert_eq!(result.emails_delivered, 0);
        assert_eq!(result.webhooks_delivered, 0);

        owned.finish().await;
    }

    #[tokio::test]
    async fn emails_delivered_falls_back_to_queue_only_when_delivery_log_is_missing() {
        let owned = provision_env("ingest_queue_only_fallback").await;
        let pool = &owned.pool;
        // The combined derivation reads email_delivery_log first; without
        // that table the sweep must derive from the queue alone.
        rename_table(pool, "email_delivery_log", "email_delivery_log_gone").await;

        let day = yesterday(Utc::now());
        let t_qfb = unique_tenant("ing_q_fallback_tenant");
        crate::test_support::seed_tenant(pool, &t_qfb, "growth").await;
        seed_sent_queue_row(pool, &t_qfb, day).await;

        let result = sweep_derived_usage(pool, Utc::now()).await.expect("sweep");
        assert_eq!(result.emails_delivered, 1, "one sent queue row derived");
        assert!(
            result.skipped_sources.is_empty(),
            "queue-only derive is not a skip: {:?}",
            result.skipped_sources
        );

        // Re-running derives nothing new (marker idempotency).
        let rerun = sweep_derived_usage(pool, Utc::now()).await.expect("rerun");
        assert_eq!(rerun.emails_delivered, 0);

        owned.finish().await;
    }

    #[tokio::test]
    async fn full_sweep_derives_every_source_and_reconciles_with_candidates() {
        let owned = provision_env("ingest_full_sweep").await;
        let pool = &owned.pool;
        let tenant = &unique_tenant("ing_full_t");
        crate::test_support::seed_tenant(pool, tenant, "growth").await;
        let t_full_q = unique_tenant("ing_full_q_tenant");
        crate::test_support::seed_tenant(pool, &t_full_q, "growth").await;
        let day = yesterday(Utc::now());
        let (day_start, _day_end) = day_bounds(day);

        // Reserved ≫ delivered: 100 reserved sends vs 10 delivered.
        for (event_type, quantity) in [("emails_sent", 100), ("emails_delivered", 10)] {
            sqlx::query(
                r#"
                INSERT INTO metering_events (id, tenant_id, event_type, quantity, "timestamp", metadata)
                VALUES ($1, $2, $3, $4, $5, '{}')
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(event_type)
            .bind(quantity)
            .bind(day_start + chrono::Duration::hours(5))
            .execute(pool)
            .await
            .expect("seed metering");
        }
        // One delivered queue row (derived) + bounce + complaint rows.
        seed_sent_queue_row(pool, &t_full_q, day).await;
        sqlx::query(
            r#"
            INSERT INTO bounce_analytics_daily (id, tenant_id, date, total_bounces, hard_bounces, soft_bounces, transient_bounces, created_at, updated_at)
            VALUES (gen_random_uuid(), $1, $2, 5, 2, 3, 0, now(), now())
            "#,
        )
        .bind(tenant)
        .bind(day)
        .execute(pool)
        .await
        .expect("seed bounce");
        sqlx::query(
            r#"
            INSERT INTO complaints (id, tenant_id, recipient, created_at)
            VALUES (gen_random_uuid(), $1, 'rcpt@example.com', $2)
            "#,
        )
        .bind(tenant)
        .bind(day_start + chrono::Duration::hours(6))
        .execute(pool)
        .await
        .expect("seed complaint");

        let now = Utc::now();
        let sweep = sweep_derived_usage(pool, now).await.expect("sweep");
        assert_eq!(sweep.emails_delivered, 1);
        assert!(sweep.skipped_sources.is_empty());

        let summary = reconcile_daily_deliveries(pool, now)
            .await
            .expect("reconciliation");
        assert_eq!(summary.day, day.to_string());
        assert!(summary.tenants_compared >= 1);
        assert_eq!(summary.reports_written, 1);
        assert_eq!(summary.overage_candidates, 1, "reserved≫delivered flags");
        assert!(summary.skipped_sources.is_empty());

        // Re-running rewrites the same idempotent report row, so no new
        // writes are counted.
        let rerun = reconcile_daily_deliveries(pool, now).await.expect("rerun");
        assert_eq!(rerun.reports_written, 0);
        assert_eq!(rerun.overage_candidates, 0);

        owned.finish().await;
    }

    /// P3 fix 2 — reconciliation must not scale DB statements with the
    /// tenant count. Before the fix each tenant-day issued its own
    /// `billing_reconciliation_reports` INSERT (the reads were already
    /// grouped); now one multi-row INSERT with `RETURNING` preserves the
    /// "only newly inserted rows count" summary. A 1-tenant run and a
    /// 3-tenant run must issue the SAME number of statements.
    #[tokio::test]
    async fn reconciliation_statement_count_is_constant_in_tenant_count() {
        use crate::test_support::query_count;

        let owned = provision_env("ingest_recon_batch").await;
        let pool = &owned.pool;
        let day = yesterday(Utc::now());
        let (day_start, _day_end) = day_bounds(day);

        async fn seed_tenant_day(pool: &sqlx::PgPool, tenant: &str, day_start: DateTime<Utc>) {
            crate::test_support::seed_tenant(pool, tenant, "growth").await;
            for (event_type, quantity) in [("emails_sent", 100), ("emails_delivered", 10)] {
                sqlx::query(
                    r#"
                    INSERT INTO metering_events (id, tenant_id, event_type, quantity, "timestamp", metadata)
                    VALUES ($1, $2, $3, $4, $5, '{}')
                    "#,
                )
                .bind(Uuid::new_v4())
                .bind(tenant)
                .bind(event_type)
                .bind(quantity)
                .bind(day_start + chrono::Duration::hours(5))
                .execute(pool)
                .await
                .expect("seed metering");
            }
        }

        let t_one = unique_tenant("ing_recon_batch_a");
        seed_tenant_day(pool, &t_one, day_start).await;
        query_count::reset();
        let first = reconcile_daily_deliveries(pool, Utc::now())
            .await
            .expect("one-tenant reconciliation");
        assert_eq!(first.reports_written, 1);
        assert_eq!(first.overage_candidates, 1);
        let one_counts = (
            query_count::count("recon.db.usage"),
            query_count::count("recon.db.bounce"),
            query_count::count("recon.db.complaint"),
            query_count::count("recon.db.write"),
        );
        assert_eq!(
            one_counts,
            (1, 2, 1, 1),
            "usage + bounce(aggregate+fallback) + complaints + ONE write"
        );

        let t_two = unique_tenant("ing_recon_batch_b");
        let t_three = unique_tenant("ing_recon_batch_c");
        seed_tenant_day(pool, &t_two, day_start).await;
        seed_tenant_day(pool, &t_three, day_start).await;
        query_count::reset();
        let second = reconcile_daily_deliveries(pool, Utc::now())
            .await
            .expect("three-tenant reconciliation");
        assert_eq!(
            second.reports_written, 2,
            "the first tenant's report is idempotent, the two new ones are written"
        );
        assert_eq!(second.overage_candidates, 2);
        let three_counts = (
            query_count::count("recon.db.usage"),
            query_count::count("recon.db.bounce"),
            query_count::count("recon.db.complaint"),
            query_count::count("recon.db.write"),
        );
        assert_eq!(
            three_counts, one_counts,
            "statement count must be constant in the tenant count"
        );

        // Integer semantics preserved: 100 reserved − 10 delivered > slack.
        let (reserved, delivered, unaccounted, candidate): (i64, i64, i64, bool) = sqlx::query_as(
            "SELECT reserved_emails, delivered_emails, unaccounted_emails, overage_candidate
                   FROM billing_reconciliation_reports
                  WHERE tenant_id = $1",
        )
        .bind(&t_three)
        .fetch_one(pool)
        .await
        .expect("reconciliation report");
        assert_eq!(
            (reserved, delivered, unaccounted, candidate),
            (100, 10, 90, true)
        );

        owned.finish().await;
    }

    #[tokio::test]
    async fn reconciliation_degrades_to_queue_and_self_hosted_sources_when_tables_are_missing() {
        let owned = provision_env("ingest_recon_degrade").await;
        let pool = &owned.pool;
        let t_degrade_b = unique_tenant("ing_degrade_bounced_t");
        let t_degrade = unique_tenant("ing_degrade_t");
        crate::test_support::seed_tenant(pool, &t_degrade_b, "growth").await;
        crate::test_support::seed_tenant(pool, &t_degrade, "growth").await;
        let day = yesterday(Utc::now());
        let (day_start, day_end) = day_bounds(day);

        // Phase 1: complaints missing, self-hosted feed present — the
        // complaint collector falls back to self_hosted_complaints.
        rename_table(pool, "complaints", "complaints_gone").await;
        sqlx::query(
            r#"
            INSERT INTO self_hosted_complaints (id, tenant_id, source_ip, complaint_type, recipient, received_at)
            VALUES (gen_random_uuid(), $1, '127.0.0.1', 'abuse', 'rcpt@example.com', $2)
            "#,
        )
        .bind(&t_degrade)
        .bind(day_start + chrono::Duration::hours(1))
        .execute(pool)
        .await
        .expect("seed self-hosted complaint");
        let complaints = collect_complaint_counts(pool, day_start, day_end)
            .await
            .expect("complaint fallback works");
        assert_eq!(complaints.get(&t_degrade), Some(&1));

        // Phase 2: the bounce aggregate table is present but EMPTY for the
        // day — the collector falls back to terminal-bounced queue rows.
        sqlx::query(
            r#"
            INSERT INTO email_queue (tenant_id, from_address, to_addresses, subject, status, created_at, updated_at)
            VALUES ($1, 'noreply@example.com', ARRAY['rcpt@example.com'], 'cov', 'bounced',
                    $2::timestamptz, $2::timestamptz)
            "#,
        )
        .bind(&t_degrade_b)
        .bind(day_start + chrono::Duration::hours(9))
        .execute(pool)
        .await
        .expect("seed bounced queue row");
        let bounces = collect_bounce_counts(pool, day)
            .await
            .expect("bounce fallback works");
        assert_eq!(bounces.get(&t_degrade_b), Some(&1));

        // Phase 3: with both aggregate tables (and the complaint fallback)
        // gone, the reconciliation summary reports every skipped source and
        // still completes.
        rename_table(
            pool,
            "bounce_analytics_daily",
            "bounce_analytics_daily_gone",
        )
        .await;
        rename_table(
            pool,
            "self_hosted_complaints",
            "self_hosted_complaints_gone",
        )
        .await;
        let now = Utc::now();
        let summary = reconcile_daily_deliveries(pool, now)
            .await
            .expect("reconciliation with missing optional tables");
        let mut skipped = summary.skipped_sources.clone();
        skipped.sort();
        assert_eq!(
            skipped,
            vec![
                "bounce_analytics_daily".to_string(),
                "complaints".to_string()
            ],
            "both missing aggregates are reported as skipped"
        );

        owned.finish().await;
    }

    #[tokio::test]
    async fn reconciliation_fails_loudly_when_bounce_or_complaint_queries_break() {
        let owned = provision_env("ingest_recon_hard_fail").await;
        let pool = &owned.pool;

        // Recreate the aggregated tables with the WRONG shape: queries now
        // fail with a non-42P01 error, which must NOT be swallowed as a
        // skip — the sweep fails loudly instead.
        rename_table(
            pool,
            "bounce_analytics_daily",
            "bounce_analytics_daily_real",
        )
        .await;
        sqlx::query("CREATE TABLE bounce_analytics_daily (unrelated integer)")
            .execute(pool)
            .await
            .expect("break bounce table");
        let broke_bounces = reconcile_daily_deliveries(pool, Utc::now()).await;
        assert!(
            matches!(&broke_bounces, Err(message) if message.contains("bounce")),
            "unexpected: {broke_bounces:?}"
        );
        // Restore and break complaints the same way.
        sqlx::query("DROP TABLE bounce_analytics_daily")
            .execute(pool)
            .await
            .expect("drop broken bounce table");
        rename_table(
            pool,
            "bounce_analytics_daily_real",
            "bounce_analytics_daily",
        )
        .await;

        rename_table(pool, "complaints", "complaints_real").await;
        sqlx::query("CREATE TABLE complaints (unrelated integer)")
            .execute(pool)
            .await
            .expect("break complaints table");
        sqlx::query("DROP TABLE self_hosted_complaints")
            .execute(pool)
            .await
            .expect("drop complaint fallback");
        let broke_complaints = reconcile_daily_deliveries(pool, Utc::now()).await;
        assert!(
            matches!(&broke_complaints, Err(message) if message.contains("complaint")),
            "unexpected: {broke_complaints:?}"
        );

        owned.finish().await;
    }
}
