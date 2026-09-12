//! Canonical analytics metric definitions — ONE source of truth for the
//! business metrics shared by the admin analytics endpoints and the control
//! plane SSR loaders.
//!
//! Conventions applied everywhere in this module:
//!
//! * **The unit is a recipient-send cohort row**: `(tenant_id, message_id,
//!   lower(recipient))`. Outcomes (`delivered` / `opened` / `clicked` /
//!   `bounced` / `complained`) attach to the send they belong to, not to the
//!   day they happened. An email sent before the window but opened inside it
//!   therefore does NOT appear in the window's `opened` numerator — it is
//!   simply not in the window's send cohort.
//! * **Cohort time = the send event occurrence.** A cohort row enters a
//!   window through the `events.timestamp` of its `sent` event (MIN when a
//!   recipient-send has several sent events). `messages.created_at` is NEVER
//!   used as a proxy for a send.
//! * **Outcome cutoff freezes history.** Outcomes are only attached when
//!   their timestamp is `>= sent_at` and `< cutoff`. The current window uses
//!   `cutoff = NOW()`; the previous window uses `cutoff = previous_period_end`
//!   (`NOW() - interval`). That is what prevents an open that happens TODAY on
//!   a send from LAST period from retroactively changing last period's
//!   numbers.
//! * **Cardinality is BOOL_OR per cohort row.** Repeat opens/clicks on one
//!   recipient-send count once. The numerator is a subset of the sent cohort,
//!   so ratios are `<= 1` by construction — they are never clamped.
//! * **Rates are `Option<f64>` fractions in `0.0..=1.0`.** A zero
//!   denominator yields `None` (absent/null), never `0` and never `inf`.
//!
//! Schema evidence for every referenced column lives in
//! `services/mail-server/migrations/` (see the doc comments on each query
//! builder below).

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use sqlx::PgPool;

use crate::error::ApiError;
use crate::state::AppState;

/// Which column carries the event type. Canonical runs use `event_type`;
/// `type` exists only on legacy runtime-provisioned schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTypeColumn {
    EventType,
    LegacyType,
}

impl EventTypeColumn {
    pub(crate) fn as_sql(self) -> &'static str {
        match self {
            Self::EventType => "event_type",
            Self::LegacyType => "type",
        }
    }
}

/// Which column carries the event-occurrence timestamp. Canonical runs use
/// `timestamp`; `created_at` exists only on legacy runtime-provisioned
/// schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTimeColumn {
    CreatedAt,
    Timestamp,
}

impl EventTimeColumn {
    pub(crate) fn as_sql(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Timestamp => "timestamp",
        }
    }
}

/// The whitelisted event column pair every canonical query is built from.
/// Values are enum variants, never user input, so the rendered SQL cannot be
/// injected through column selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventColumns {
    pub type_col: EventTypeColumn,
    pub time_col: EventTimeColumn,
}

impl Default for EventColumns {
    fn default() -> Self {
        Self {
            type_col: EventTypeColumn::EventType,
            time_col: EventTimeColumn::Timestamp,
        }
    }
}

/// Analytics windows. `interval_sql()` output is rendered into SQL as a
/// literal because it is a fixed, code-owned string (never user input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyticsRange {
    Hours24,
    Days7,
    Days30,
    Days90,
    Months12,
}

impl AnalyticsRange {
    pub(crate) fn interval_sql(self) -> &'static str {
        match self {
            Self::Hours24 => "24 hours",
            Self::Days7 => "7 days",
            Self::Days30 => "30 days",
            Self::Days90 => "90 days",
            Self::Months12 => "365 days",
        }
    }
}

pub fn parse_analytics_range(range: &str) -> AnalyticsRange {
    match range {
        "24h" => AnalyticsRange::Hours24,
        "7d" => AnalyticsRange::Days7,
        "30d" => AnalyticsRange::Days30,
        "90d" => AnalyticsRange::Days90,
        "12m" => AnalyticsRange::Months12,
        _ => AnalyticsRange::Days7,
    }
}

pub fn select_event_columns(type_col: Option<&str>, time_col: Option<&str>) -> EventColumns {
    EventColumns {
        type_col: match type_col {
            Some("type") => EventTypeColumn::LegacyType,
            _ => EventTypeColumn::EventType,
        },
        time_col: match time_col {
            Some("timestamp") => EventTimeColumn::Timestamp,
            _ => EventTimeColumn::CreatedAt,
        },
    }
}

/// Detect which of the candidate columns exists on `table` (canonical
/// production schemas have `event_type`/`timestamp`; runtime-provisioned
/// legacy schemas may have `type`/`created_at`).
pub async fn detect_column(db: &PgPool, table: &str, candidates: &[&str]) -> Option<String> {
    for col in candidates {
        let exists: Option<(bool,)> = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2)",
        )
        .bind(table)
        .bind(*col)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
        if exists.map(|r| r.0).unwrap_or(false) {
            return Some((*col).to_string());
        }
    }
    None
}

pub async fn detect_event_columns(state: &AppState) -> EventColumns {
    let type_col = detect_column(&state.db, "events", &["event_type", "type"]).await;
    let time_col = detect_column(&state.db, "events", &["timestamp", "created_at"]).await;

    select_event_columns(type_col.as_deref(), time_col.as_deref())
}

/// Parse the code-owned window strings this module accepts ("24 hours",
/// "7 days", "365 days", …) into a duration. Unknown units are an internal
/// configuration error, never silently treated as a zero-width window.
fn interval_duration(interval: &str) -> Result<ChronoDuration, ApiError> {
    let mut parts = interval.split_whitespace();
    let amount = parts.next().and_then(|v| v.parse::<i64>().ok());
    let unit = parts.next();
    let (Some(amount), Some(unit)) = (amount, unit) else {
        return Err(ApiError::Internal(format!(
            "invalid analytics interval: {interval:?}"
        )));
    };
    if amount < 0 {
        return Err(ApiError::Internal(format!(
            "negative analytics interval: {interval:?}"
        )));
    }
    match unit {
        "second" | "seconds" => Ok(ChronoDuration::seconds(amount)),
        "minute" | "minutes" => Ok(ChronoDuration::minutes(amount)),
        "hour" | "hours" => Ok(ChronoDuration::hours(amount)),
        "day" | "days" => Ok(ChronoDuration::days(amount)),
        "week" | "weeks" => Ok(ChronoDuration::weeks(amount)),
        other => Err(ApiError::Internal(format!(
            "unsupported analytics interval unit: {other:?}"
        ))),
    }
}

/// The `sent_cohort` CTE: one row per recipient-send whose `sent` event
/// falls in `[window_start, window_end)`.
///
/// Columns referenced: `events.tenant_id` / `message_id` / `recipient` /
/// `event_type` / `timestamp` — migration
/// `075_create_missing_tables.sql:30-49` (events DDL) and
/// `090_widen_events_id_columns.sql:25-32` (`domain_id`/`campaign_id` are
/// TEXT; `message_id` stays VARCHAR(64), which fits a UUID).
fn sent_cohort_cte(type_col: &str, time_col: &str) -> String {
    format!(
        "sent_cohort AS (
            SELECT tenant_id, message_id, lower(recipient) AS recipient,
                   MIN({time_col}) AS sent_at
            FROM events
            WHERE {type_col} = 'sent'
              AND {time_col} >= $1
              AND {time_col} < $2
              AND ($3::text IS NULL OR tenant_id = $3)
            GROUP BY tenant_id, message_id, lower(recipient)
        )"
    )
}

/// The `outcomes` CTE: `BOOL_OR` per cohort row over events for the SAME
/// `(tenant_id, message_id, lower(recipient))` at or after the send and
/// strictly before the cutoff (`$4`).
///
/// A cohort row with no matching outcome events keeps every BOOL_OR false
/// and is still counted by the outer `COUNT(*)` — a send without feedback is
/// a delivered-with-no-evidence send, not a missing send.
///
/// `lower(e.recipient) = s.recipient` is never true for a NULL recipient, so
/// hostile NULL-recipient rows can never make one cohort absorb another.
fn outcomes_cte(type_col: &str, time_col: &str) -> String {
    format!(
        "outcomes AS (
            SELECT s.tenant_id, s.message_id, s.recipient, s.sent_at,
                   BOOL_OR(e.{type_col} = 'delivered')  AS delivered,
                   BOOL_OR(e.{type_col} = 'opened')     AS opened,
                   BOOL_OR(e.{type_col} = 'clicked')    AS clicked,
                   BOOL_OR(e.{type_col} = 'bounced')    AS bounced,
                   BOOL_OR(e.{type_col} = 'complained') AS complained
            FROM sent_cohort s
            LEFT JOIN events e
              ON  e.tenant_id = s.tenant_id
              AND e.message_id = s.message_id
              AND lower(e.recipient) = s.recipient
              AND e.{time_col} >= s.sent_at
              AND e.{time_col} < $4
            GROUP BY s.tenant_id, s.message_id, s.recipient, s.sent_at
        )"
    )
}

/// Cohort aggregate SQL. `$1`/`$2` are the window bounds (timestamptz),
/// `$3` the tenant (NULL = fleet-wide), `$4` the outcome cutoff.
///
/// Current window: `$1 = NOW() - interval`, `$2 = NOW()`, `$4 = NOW()`.
/// Previous window: `$1 = NOW() - 2*interval`, `$2 = NOW() - interval`,
/// `$4 = NOW() - interval` — the previous period's END. The cutoff is what
/// makes a past period immutable: an open that lands today cannot change
/// last period's `opened` numerator.
pub fn send_cohort_counts_sql(columns: EventColumns) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();

    format!(
        "WITH {},\n{}\nSELECT COUNT(*)::bigint AS sent,
            COUNT(*) FILTER (WHERE delivered)::bigint AS delivered,
            COUNT(*) FILTER (WHERE opened)::bigint AS opened,
            COUNT(*) FILTER (WHERE clicked)::bigint AS clicked,
            COUNT(*) FILTER (WHERE bounced)::bigint AS bounced,
            COUNT(*) FILTER (WHERE complained)::bigint AS complained
         FROM outcomes",
        sent_cohort_cte(type_col, time_col),
        outcomes_cte(type_col, time_col),
    )
}

/// Cohort time-series SQL: each day is the `sent_at` day of the cohort, with
/// the same outcome cutoff (`$4`) as [`send_cohort_counts_sql`]. Opens are
/// NOT bucketed on the day they happened — the chart is a send-cohort
/// engagement series, so an open attaches to the day its send went out.
pub fn send_cohort_time_series_sql(columns: EventColumns) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();

    format!(
        "WITH {},\n{}\nSELECT DATE(sent_at)::text AS d,
            COUNT(*)::bigint AS sent,
            COUNT(*) FILTER (WHERE delivered)::bigint AS delivered,
            COUNT(*) FILTER (WHERE opened)::bigint AS opened,
            COUNT(*) FILTER (WHERE clicked)::bigint AS clicked,
            COUNT(*) FILTER (WHERE bounced)::bigint AS bounced,
            COUNT(*) FILTER (WHERE complained)::bigint AS complained
         FROM outcomes
         GROUP BY d ORDER BY d ASC",
        sent_cohort_cte(type_col, time_col),
        outcomes_cte(type_col, time_col),
    )
}

/// Send-cohort counts for every metric the engagement surfaces report.
///
/// Each count is a number of cohort rows `(tenant_id, message_id,
/// lower(recipient))`: one recipient-send contributes at most 1 to `sent`
/// and at most 1 to each outcome numerator, no matter how many
/// opens/clicks/sent-event copies it generated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendCohortCounts {
    /// Recipient-sends with at least one successful `sent` event in the
    /// window (counted by send time, not by later outcomes).
    pub sent: i64,
    /// Cohort rows with at least one `delivered` event at/after the send.
    pub delivered: i64,
    /// Cohort rows with at least one `opened` event (repeat opens do not
    /// add).
    pub opened: i64,
    /// Cohort rows with at least one `clicked` event.
    pub clicked: i64,
    /// Cohort rows with at least one `bounced` event.
    pub bounced: i64,
    /// Cohort rows with at least one `complained` event.
    pub complained: i64,
}

impl SendCohortCounts {
    /// Fraction of the send cohort, in `0.0..=1.0`. A zero denominator
    /// yields `None` — absent, never a fabricated `0` and never `inf`.
    /// Because every numerator counts cohort rows that also have a send
    /// event, the result cannot exceed 1.0 by construction.
    pub fn rate_of_sent(&self, numerator: i64) -> Option<f64> {
        if self.sent > 0 {
            Some(numerator as f64 / self.sent as f64)
        } else {
            None
        }
    }

    pub fn delivery_rate(&self) -> Option<f64> {
        self.rate_of_sent(self.delivered)
    }

    pub fn open_rate(&self) -> Option<f64> {
        self.rate_of_sent(self.opened)
    }

    pub fn click_rate(&self) -> Option<f64> {
        self.rate_of_sent(self.clicked)
    }

    pub fn bounce_rate(&self) -> Option<f64> {
        self.rate_of_sent(self.bounced)
    }

    pub fn complaint_rate(&self) -> Option<f64> {
        self.rate_of_sent(self.complained)
    }
}

/// One `sent_at` day of send-cohort engagement counts.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendCohortTimeSeriesPoint {
    pub date: String,
    pub sent: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
    pub bounced: i64,
    pub complained: i64,
}

async fn run_cohort_counts(
    db: &PgPool,
    tenant_id: Option<&str>,
    columns: EventColumns,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    outcome_cutoff: DateTime<Utc>,
) -> Result<SendCohortCounts, ApiError> {
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&send_cohort_counts_sql(columns))
        .bind(window_start)
        .bind(window_end)
        .bind(tenant_id)
        .bind(outcome_cutoff)
        .fetch_one(db)
        .await?;

    Ok(SendCohortCounts {
        sent: row.0,
        delivered: row.1,
        opened: row.2,
        clicked: row.3,
        bounced: row.4,
        complained: row.5,
    })
}

/// Fetch the canonical send-cohort counts for a window. The outcome cutoff
/// is `NOW()`: feedback that arrives after this instant belongs to the next
/// look, it does not change what is reported now.
///
/// `tenant_id = None` means fleet-wide (system tenant); `Some` scopes to one
/// tenant.
pub async fn send_cohort_counts(
    db: &PgPool,
    tenant_id: Option<&str>,
    interval: &str,
    columns: EventColumns,
) -> Result<SendCohortCounts, ApiError> {
    let now = Utc::now();
    let window = interval_duration(interval)?;
    run_cohort_counts(db, tenant_id, columns, now - window, now, now).await
}

/// Fetch the canonical send-cohort counts for the window IMMEDIATELY BEFORE
/// the current one: `[NOW() - 2*interval, NOW() - interval)`.
///
/// The outcome cutoff is that window's END (`NOW() - interval`), NOT now.
/// This is the period-over-period freeze: a send from last period that is
/// opened today is still `sent` in last period, but the open that happened
/// after last period ended can never retroactively raise last period's
/// `opened`.
pub async fn send_cohort_counts_previous(
    db: &PgPool,
    tenant_id: Option<&str>,
    interval: &str,
    columns: EventColumns,
) -> Result<SendCohortCounts, ApiError> {
    let now = Utc::now();
    let window = interval_duration(interval)?;
    let previous_end = now - window;
    run_cohort_counts(
        db,
        tenant_id,
        columns,
        previous_end - window,
        previous_end,
        previous_end,
    )
    .await
}

/// Fetch the canonical send-cohort time series for a window, bucketed by
/// the cohort's `sent_at` day with outcomes attached to that cohort.
pub async fn send_cohort_time_series(
    db: &PgPool,
    tenant_id: Option<&str>,
    range: AnalyticsRange,
    columns: EventColumns,
) -> Result<Vec<SendCohortTimeSeriesPoint>, ApiError> {
    let now = Utc::now();
    let window = interval_duration(range.interval_sql())?;

    let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64, i64, i64)>(
        &send_cohort_time_series_sql(columns),
    )
    .bind(now - window)
    .bind(now)
    .bind(tenant_id)
    .bind(now)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(date, sent, delivered, opened, clicked, bounced, complained)| {
                SendCohortTimeSeriesPoint {
                    date,
                    sent,
                    delivered,
                    opened,
                    clicked,
                    bounced,
                    complained,
                }
            },
        )
        .collect())
}

// ─── Explicit partial availability ─────────────────────────────────────

/// Availability of one genuinely-optional metric value.
///
/// Required operational data (customers, revenue, signups, …) must NEVER use
/// this to swallow a database failure into a default: a failed required
/// query is an `Err` that propagates. `MetricState` exists only for metrics
/// whose ABSENCE is a legitimate state (e.g. an average over an empty
/// population) while a failed READ is still distinguishable from an empty
/// one.
///
/// Serialized as `{"available": true, "value": …}` or
/// `{"available": false, "reason": "…"}`, so the UI can render the reason
/// instead of a fabricated zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricState<T> {
    Available(T),
    Unavailable { reason: &'static str },
}

impl<T> MetricState<T> {
    pub fn available(&self) -> Option<&T> {
        match self {
            Self::Available(value) => Some(value),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn unavailable_reason(&self) -> Option<&'static str> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }

    /// Map the available value, preserving an unavailable state.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> MetricState<U> {
        match self {
            Self::Available(value) => MetricState::Available(f(value)),
            Self::Unavailable { reason } => MetricState::Unavailable { reason },
        }
    }
}

impl<T: Serialize> Serialize for MetricState<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        match self {
            Self::Available(value) => {
                map.serialize_entry("available", &true)?;
                map.serialize_entry("value", value)?;
            }
            Self::Unavailable { reason } => {
                map.serialize_entry("available", &false)?;
                map.serialize_entry("reason", reason)?;
            }
        }
        map.end()
    }
}

// ─── Recipient-mailbox-provider breakdown ──────────────────────────────

/// Provider identity source for the sent-event breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSource {
    /// A persisted normalized recipient-provider dimension
    /// (`events.recipient_provider`, migration
    /// `202_sales_feedback_delivery_binding.sql:150-167`) was found and
    /// used, or every bucket came from such a value.
    Persisted,
    /// No persisted dimension exists: only well-known consumer mailbox
    /// domains are classified, from the recipient-domain suffix. Custom
    /// domains hosted by Google Workspace / Microsoft 365 therefore appear
    /// as 'Other' — every row is labelled `inferred`.
    InferredFromConsumerDomain,
}

impl ProviderSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persisted => "persisted",
            Self::InferredFromConsumerDomain => "inferred",
        }
    }
}

/// One provider bucket: count of recipient-send cohort rows to that
/// provider.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCount {
    pub provider: String,
    pub count: i64,
    /// `true` when the provider was derived from the recipient-domain
    /// suffix rather than read from a persisted provider dimension. The UI
    /// must not present inferred buckets as authoritative.
    pub inferred: bool,
}

/// Provider breakdown result plus the provenance needed to label it.
#[derive(Debug, Clone)]
pub struct ProviderBreakdown {
    pub providers: Vec<ProviderCount>,
    pub source: ProviderSource,
    /// Non-empty when any bucket is inferred; callers surface this in the
    /// response so the UI cannot present the fallback as authoritative.
    pub note: Option<String>,
}

/// Suffix classification for well-known CONSUMER mailbox domains, where the
/// domain suffix IS the mailbox provider (a plain `@gmail.com` address is a
/// Gmail mailbox). Hosted custom domains are deliberately excluded: a
/// `@acme.com` address hosted by Google Workspace is not classifiable from
/// the address alone, so it lands in 'Other' instead of being mislabelled.
const CONSUMER_PROVIDER_CASE: &str = "CASE
    WHEN LOWER(recipient) LIKE '%@gmail.com' OR LOWER(recipient) LIKE '%@googlemail.com' THEN 'Gmail'
    WHEN LOWER(recipient) LIKE '%@yahoo.%' OR LOWER(recipient) LIKE '%@ymail.com' OR LOWER(recipient) LIKE '%@rocketmail.com' THEN 'Yahoo'
    WHEN LOWER(recipient) LIKE '%@outlook.%' OR LOWER(recipient) LIKE '%@hotmail.%'
      OR LOWER(recipient) LIKE '%@live.com' OR LOWER(recipient) LIKE '%@msn.com' THEN 'Microsoft'
    WHEN LOWER(recipient) LIKE '%@icloud.com' OR LOWER(recipient) LIKE '%@me.com' OR LOWER(recipient) LIKE '%@mac.com' THEN 'Apple iCloud'
    WHEN LOWER(recipient) LIKE '%@aol.com' THEN 'AOL'
    WHEN LOWER(recipient) LIKE '%@proton.me' OR LOWER(recipient) LIKE '%@protonmail.com' THEN 'Proton'
    WHEN LOWER(recipient) LIKE '%@gmx.%' OR LOWER(recipient) LIKE '%@mail.com'
      OR LOWER(recipient) LIKE '%@zoho.com' OR LOWER(recipient) LIKE '%@yandex.%' THEN 'Other consumer'
    ELSE 'Other'
END";

const INFERRED_PROVIDER_NOTE: &str = "Provider identity is inferred from well-known consumer recipient-domain suffixes only for rows with no persisted recipient-provider value. Custom domains hosted by Google Workspace / Microsoft 365 and other provider-hosted domains appear as 'Other' unless recipient_provider was persisted at delivery time (provider_source = 'mx_resolved'). Inferred buckets are not authoritative.";

/// Read the provider breakdown for the sent population of the window.
///
/// Preference order:
/// 1. a persisted normalized provider on the `sent` event
///    (`recipient_provider`, migration 202) — read it, never re-derive.
///    `provider_source` is passed through so an `inferred` value persisted
///    at write time stays labelled inferred;
/// 2. for rows with NO persisted provider (historical rows written before
///    migration 202), classify by recipient-domain suffix for well-known
///    consumer domains ONLY and label those buckets `inferred: true` with a
///    response note. Hosted custom domains are never guessed.
///
/// Counts are distinct `(message_id, lower(recipient))` cohort rows — the
/// same recipient-send unit as every other metric here.
pub async fn provider_breakdown(
    db: &PgPool,
    tenant_id: Option<&str>,
    interval: &str,
    columns: EventColumns,
) -> Result<ProviderBreakdown, ApiError> {
    let now = Utc::now();
    let window = interval_duration(interval)?;
    let window_start = now - window;

    let persisted_column = detect_column(db, "events", &["recipient_provider", "provider"]).await;
    let has_source_column = detect_column(db, "events", &["provider_source"])
        .await
        .is_some();

    if let Some(column) = persisted_column {
        let type_col = columns.type_col.as_sql();
        let time_col = columns.time_col.as_sql();
        // Historical rows (NULL/blank provider) keep the consumer-suffix
        // inference and are explicitly labelled 'inferred'. Persisted rows
        // pass through provider_source, defaulting to 'persisted' only when
        // the schema has no source column at all.
        let persisted_provider = format!(
            "CASE WHEN {column} IS NOT NULL AND btrim({column}::text) <> '' \
                  THEN {column}::text ELSE {CONSUMER_PROVIDER_CASE} END"
        );
        let source_expr = if has_source_column {
            format!(
                "CASE WHEN {column} IS NOT NULL AND btrim({column}::text) <> '' \
                      THEN COALESCE(NULLIF(btrim(provider_source), ''), 'persisted') \
                      ELSE 'inferred' END"
            )
        } else {
            format!(
                "CASE WHEN {column} IS NOT NULL AND btrim({column}::text) <> '' \
                      THEN 'persisted' ELSE 'inferred' END"
            )
        };

        let rows = sqlx::query_as::<_, (String, String, i64)>(&format!(
            "WITH send_rows AS (
                SELECT message_id,
                       COALESCE(lower(recipient), '') AS recipient_lc,
                       ({persisted_provider}) AS provider,
                       ({source_expr}) AS source
                FROM events
                WHERE {time_col} >= $1 AND {time_col} < $2
                  AND ($3::text IS NULL OR tenant_id = $3)
                  AND {type_col} = 'sent'
            )
            SELECT provider, source,
                   COUNT(DISTINCT (message_id, recipient_lc))::bigint AS cnt
            FROM send_rows
            GROUP BY provider, source
            ORDER BY cnt DESC"
        ))
        .bind(window_start)
        .bind(now)
        .bind(tenant_id)
        .fetch_all(db)
        .await?;

        return Ok(assembled_breakdown(rows.into_iter().map(
            |(provider, source, count)| (provider, source == "inferred", count),
        )));
    }

    // No persisted dimension: consumer-suffix fallback, explicitly inferred.
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let rows = sqlx::query_as::<_, (String, i64)>(&format!(
        "SELECT {CONSUMER_PROVIDER_CASE} as provider,
                COUNT(DISTINCT (message_id, COALESCE(lower(recipient), '')))::bigint as cnt
         FROM events
         WHERE {time_col} >= $1 AND {time_col} < $2
           AND ($3::text IS NULL OR tenant_id = $3)
           AND {type_col} = 'sent'
         GROUP BY provider ORDER BY cnt DESC"
    ))
    .bind(window_start)
    .bind(now)
    .bind(tenant_id)
    .fetch_all(db)
    .await?;

    Ok(assembled_breakdown(
        rows.into_iter()
            .map(|(provider, count)| (provider, true, count)),
    ))
}

fn assembled_breakdown(rows: impl Iterator<Item = (String, bool, i64)>) -> ProviderBreakdown {
    let mut providers = Vec::new();
    let mut any_inferred = false;
    let mut any_authoritative = false;
    for (provider, inferred, count) in rows {
        any_inferred |= inferred;
        any_authoritative |= !inferred;
        providers.push(ProviderCount {
            provider,
            count,
            inferred,
        });
    }

    ProviderBreakdown {
        providers,
        source: if any_authoritative {
            ProviderSource::Persisted
        } else {
            ProviderSource::InferredFromConsumerDomain
        },
        note: any_inferred.then(|| INFERRED_PROVIDER_NOTE.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_columns_are_event_type_and_timestamp() {
        let columns = EventColumns::default();
        assert_eq!(columns.type_col.as_sql(), "event_type");
        assert_eq!(columns.time_col.as_sql(), "timestamp");
    }

    #[test]
    fn interval_duration_parses_the_code_owned_units() {
        assert_eq!(
            interval_duration("24 hours").expect("hours"),
            ChronoDuration::hours(24)
        );
        assert_eq!(
            interval_duration("30 days").expect("days"),
            ChronoDuration::days(30)
        );
        assert_eq!(
            interval_duration("2 weeks").expect("weeks"),
            ChronoDuration::weeks(2)
        );
        assert!(interval_duration("tomorrow").is_err());
        assert!(interval_duration("-3 days").is_err());
    }

    #[test]
    fn cohort_sql_is_send_cohort_with_bool_or_outcomes() {
        let sql = send_cohort_counts_sql(EventColumns::default());

        // The unit is a recipient-send: grouped by tenant/message/recipient.
        assert!(sql.contains("lower(recipient) AS recipient"));
        assert!(sql.contains("GROUP BY tenant_id, message_id, lower(recipient)"));
        // One MIN(sent_at) per cohort, so a duplicate sent event cannot
        // create a second cohort row.
        assert!(sql.contains("MIN(timestamp) AS sent_at"));
        // Outcomes attach to the cohort (BOOL_OR), never counted as events.
        assert!(sql.contains("BOOL_OR(e.event_type = 'opened')"));
        assert!(sql.contains("BOOL_OR(e.event_type = 'complained')"));
        assert!(!sql.contains("COUNT(DISTINCT message_id)"));
        assert!(!sql.contains("COUNT(*) FILTER (WHERE event_type"));
        // Window + outcome cutoff are bound parameters; the cutoff is a
        // separate parameter from the window end.
        assert!(sql.contains("timestamp >= $1"));
        assert!(sql.contains("timestamp < $2"));
        assert!(sql.contains("e.timestamp < $4"));
        assert!(sql.contains("$3::text IS NULL OR tenant_id = $3"));
    }

    #[test]
    fn cohort_time_series_buckets_by_sent_at_not_event_day() {
        let sql = send_cohort_time_series_sql(EventColumns::default());

        assert!(sql.contains("DATE(sent_at)::text"));
        assert!(!sql.contains("DATE(timestamp)::text"));
        assert!(sql.contains("GROUP BY d ORDER BY d ASC"));
        assert!(sql.contains("BOOL_OR(e.event_type = 'delivered')"));
        // The per-day bounced/complained columns share the same cohort unit.
        assert!(sql.contains("BOOL_OR(e.event_type = 'bounced')"));
    }

    /// A cohort numerator is a subset of the sent cohort: it can never be
    /// larger, so engagement ratios need no clamping.
    #[test]
    fn rates_from_cohort_counts_cannot_exceed_one() {
        let counts = SendCohortCounts {
            sent: 100,
            delivered: 98,
            opened: 100, // one distinct cohort opened, 100 total open events
            clicked: 100,
            bounced: 1,
            complained: 0,
        };

        assert_eq!(counts.open_rate(), Some(1.0));
        assert_eq!(counts.click_rate(), Some(1.0));
        assert!(counts.open_rate().expect("rate") <= 1.0);
        assert!(counts.click_rate().expect("rate") <= 1.0);
        assert!(counts.delivery_rate().expect("rate") <= 1.0);
        assert!(counts.bounce_rate().expect("rate") <= 1.0);
        assert!(counts.complaint_rate().expect("rate") <= 1.0);
    }

    /// Zero denominator yields `None` — absent, not `0`, not `inf`.
    #[test]
    fn zero_send_population_yields_none_rate_not_zero() {
        let counts = SendCohortCounts::default();
        assert_eq!(counts.open_rate(), None);
        assert_eq!(counts.delivery_rate(), None);
        assert_eq!(counts.click_rate(), None);
        assert_eq!(counts.bounce_rate(), None);
        assert_eq!(counts.complaint_rate(), None);
    }

    #[test]
    fn metric_state_serializes_reason_instead_of_a_value() {
        let available: MetricState<f64> = MetricState::Available(0.5);
        let json = serde_json::to_value(&available).expect("serialize");
        assert_eq!(json["available"], serde_json::json!(true));
        assert_eq!(json["value"], serde_json::json!(0.5));

        let unavailable: MetricState<f64> = MetricState::Unavailable {
            reason: "query failed",
        };
        let json = serde_json::to_value(&unavailable).expect("serialize");
        assert_eq!(json["available"], serde_json::json!(false));
        assert_eq!(json["reason"], serde_json::json!("query failed"));
        assert!(json.get("value").is_none());

        assert!(unavailable.available().is_none());
        assert_eq!(unavailable.unavailable_reason(), Some("query failed"));
    }

    #[test]
    fn consumer_fallback_classifies_only_well_known_domains() {
        // The fallback CASE exists but hosted/unknown domains must land in
        // 'Other' rather than being guessed from a custom suffix.
        assert!(CONSUMER_PROVIDER_CASE.contains("@gmail.com"));
        assert!(CONSUMER_PROVIDER_CASE.contains("@outlook."));
        assert!(CONSUMER_PROVIDER_CASE.contains("ELSE 'Other'"));
        assert!(!CONSUMER_PROVIDER_CASE.contains("google.com' THEN"));
    }

    #[test]
    fn inferred_provider_note_is_explicit_about_provenance() {
        assert!(INFERRED_PROVIDER_NOTE.contains("inferred"));
        assert!(INFERRED_PROVIDER_NOTE.contains("not authoritative"));
    }

    #[test]
    fn assembled_breakdown_flags_mixed_provenance() {
        // An mx_resolved bucket plus an inferred bucket: the source is
        // persisted, the inferred row stays flagged, and the note explains
        // the mix.
        let breakdown = assembled_breakdown(
            vec![
                ("google_workspace".to_string(), false, 5),
                ("Other".to_string(), true, 2),
            ]
            .into_iter(),
        );
        assert_eq!(breakdown.source, ProviderSource::Persisted);
        assert!(breakdown.providers[0].inferred == false);
        assert!(breakdown.providers[1].inferred);
        assert!(breakdown
            .note
            .as_deref()
            .expect("note")
            .contains("not authoritative"));

        // All-inferred fallback: source says so.
        let fallback = assembled_breakdown(vec![("Gmail".to_string(), true, 1)].into_iter());
        assert_eq!(fallback.source, ProviderSource::InferredFromConsumerDomain);
        assert!(fallback.providers.iter().all(|p| p.inferred));
    }

    // ── DB-backed adversarial tests (canonical schema) ─────────────────

    fn seed_event(
        pool: sqlx::PgPool,
        tenant: String,
        message: String,
        event: &'static str,
        recipient: Option<&'static str>,
        minutes_ago: i64,
    ) -> impl std::future::Future<Output = ()> {
        async move {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
                 VALUES ($1, $2, $3, $4, $5, NOW() - make_interval(mins => $6::int))",
            )
            .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
            .bind(&tenant)
            .bind(&message)
            .bind(event)
            .bind(recipient)
            .bind(minutes_ago as i32)
            .execute(&pool)
            .await
            .expect("seed event");
        }
    }

    /// Adversarial 1 + 3 + 7: a send before the window with an open inside
    /// the window is NOT in the cohort; repeat opens count once; a cohort
    /// with no outcomes still counts as sent; case-differing recipients
    /// collapse to one cohort row; NULL/empty recipients are handled.
    #[tokio::test]
    async fn cohort_boundaries_repeats_and_hostile_recipients() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_cohort_bounds").await else {
            eprintln!(
                "skipping cohort_boundaries_repeats_and_hostile_recipients: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);

        // (a) Sent BEFORE the 7-day window, opened INSIDE it: the open must
        // not inflate the current period's open rate.
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-old"),
            "sent",
            Some("old@example.com"),
            10 * 24 * 60,
        )
        .await;
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-old"),
            "opened",
            Some("old@example.com"),
            60,
        )
        .await;

        // (b) One recipient-send opened three times: counts once.
        for _ in 0..3 {
            seed_event(
                pool.clone(),
                tenant.clone(),
                format!("msg-{suffix}-multi"),
                "opened",
                Some("repeat@example.com"),
                50,
            )
            .await;
        }
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-multi"),
            "sent",
            Some("repeat@example.com"),
            55,
        )
        .await;

        // (c) A cohort with NO outcome events: still counted in sent.
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-silent"),
            "sent",
            Some("silent@example.com"),
            45,
        )
        .await;

        // (d) Case-differing recipients of one message collapse to ONE
        // cohort row (the open attaches to that row).
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-case"),
            "sent",
            Some("User@Example.COM"),
            40,
        )
        .await;
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-case"),
            "sent",
            Some("user@example.com"),
            39,
        )
        .await;
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-case"),
            "opened",
            Some("USER@example.com"),
            38,
        )
        .await;

        // (e) Hostile recipients: NULL and empty must not panic and must
        // stay separate cohort rows (NULL never absorbs another row).
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-null"),
            "sent",
            None,
            30,
        )
        .await;
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}-empty"),
            "sent",
            Some(""),
            29,
        )
        .await;

        let counts = send_cohort_counts(&pool, Some(&tenant), "7 days", EventColumns::default())
            .await
            .expect("cohort query must execute");

        // Sent: multi + silent + case (2 sends collapse to 1) + null + empty
        // = 5. The 10-day-old send is outside the window.
        assert_eq!(counts.sent, 5, "send cohort unit is recipient-send");
        // Opened: multi (3 events → 1) + case (1) = 2. The old send's open
        // is NOT in the cohort.
        assert_eq!(
            counts.opened, 2,
            "an open inside the window on a send outside it is not in the cohort"
        );
        let open_rate = counts.open_rate().expect("sent > 0");
        assert!(
            (open_rate - 2.0 / 5.0).abs() < 1e-9,
            "open rate is cohort-based, got {open_rate}"
        );
        assert!(open_rate <= 1.0);

        pool.close().await;
    }

    /// A send three days ago opened TODAY appears in the series on the SEND
    /// day (`sent_at`), not the open's day: the chart is a send-cohort
    /// engagement series, so an open attaches to the cohort it belongs to.
    #[tokio::test]
    async fn time_series_buckets_outcomes_on_the_send_day() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_cohort_series_day").await else {
            eprintln!(
                "skipping time_series_buckets_outcomes_on_the_send_day: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message = format!("msg-{suffix}");

        seed_event(
            pool.clone(),
            tenant.clone(),
            message.clone(),
            "sent",
            Some("user@example.com"),
            3 * 24 * 60,
        )
        .await;
        seed_event(
            pool.clone(),
            tenant.clone(),
            message.clone(),
            "opened",
            Some("user@example.com"),
            5,
        )
        .await;

        let series = send_cohort_time_series(
            &pool,
            Some(&tenant),
            AnalyticsRange::Days7,
            EventColumns::default(),
        )
        .await
        .expect("cohort series query must execute");

        assert_eq!(series.len(), 1, "only the send day is a bucket: {series:?}");
        assert_eq!(series[0].sent, 1);
        assert_eq!(
            series[0].opened, 1,
            "the open attaches to its send cohort, not to today"
        );

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert_ne!(
            series[0].date, today,
            "the cohort bucket is the send day, not the day the open happened"
        );

        pool.close().await;
    }

    /// Adversarial 2: the previous period's outcome cutoff is the previous
    /// period's END. A send in the prior period opened NOW stays
    /// sent=1/opened=0 in that prior period — history cannot be rewritten.
    #[tokio::test]
    async fn previous_period_is_frozen_at_its_own_end() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_cohort_freeze").await else {
            eprintln!("skipping previous_period_is_frozen_at_its_own_end: no TEST_DATABASE_URL");
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);

        // Sent 10 days ago (inside the PREVIOUS 7-day window), opened NOW.
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}"),
            "sent",
            Some("user@example.com"),
            10 * 24 * 60,
        )
        .await;
        seed_event(
            pool.clone(),
            tenant.clone(),
            format!("msg-{suffix}"),
            "opened",
            Some("user@example.com"),
            0,
        )
        .await;

        let current = send_cohort_counts(&pool, Some(&tenant), "7 days", EventColumns::default())
            .await
            .expect("current cohort query");
        assert_eq!(current.sent, 0, "the send is outside the current window");
        assert_eq!(current.opened, 0);

        let previous =
            send_cohort_counts_previous(&pool, Some(&tenant), "7 days", EventColumns::default())
                .await
                .expect("previous cohort query");
        assert_eq!(previous.sent, 1, "the send belongs to the previous period");
        assert_eq!(
            previous.opened, 0,
            "an open after the previous period ended must not retroactively \
             change the previous period (cutoff = previous period end)"
        );
        assert_eq!(previous.open_rate(), Some(0.0));

        pool.close().await;
    }

    /// Adversarial 5 for the growth module is in `growth_analytics`; here we
    /// prove the cohort aggregate itself never returns Ok(0) when the
    /// relation is broken — the error propagates as an Err.
    #[tokio::test]
    async fn cohort_query_failure_is_an_error_not_zero_counts() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_cohort_failure").await else {
            eprintln!(
                "skipping cohort_query_failure_is_an_error_not_zero_counts: no TEST_DATABASE_URL"
            );
            return;
        };

        sqlx::query("ALTER TABLE events RENAME TO events_renamed_for_failure_test")
            .execute(&pool)
            .await
            .expect("rename events (throwaway test database)");

        let result = send_cohort_counts(&pool, None, "7 days", EventColumns::default()).await;
        assert!(
            result.is_err(),
            "a broken events relation must be an error, never Ok(0 counts)"
        );

        pool.close().await;
    }

    /// Adversarial 6: provenance. A persisted `mx_resolved` value beats the
    /// suffix guess for a hosted custom domain; a persisted `inferred`
    /// value is labelled inferred.
    #[tokio::test]
    async fn provider_breakdown_prefers_mx_resolved_and_labels_inferred() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_provider_provenance").await
        else {
            eprintln!(
                "skipping provider_breakdown_prefers_mx_resolved_and_labels_inferred: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);

        let seed = |message: String,
                    recipient: &'static str,
                    provider: Option<&'static str>,
                    source: Option<&'static str>| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            async move {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, recipient,
                                         recipient_provider, provider_source, timestamp)
                     VALUES ($1, $2, $3, 'sent', $4, $5, $6, NOW())",
                )
                .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
                .bind(&tenant)
                .bind(&message)
                .bind(recipient)
                .bind(provider)
                .bind(source)
                .execute(&pool)
                .await
                .expect("seed sent event");
            }
        };

        // A custom domain hosted by Google Workspace, resolved via MX at
        // delivery time: must be reported as google_workspace, NOT Gmail,
        // and NOT inferred.
        seed(
            format!("msg-{suffix}-mx"),
            "ceo@acme-corp.example",
            Some("google_workspace"),
            Some("mx_resolved"),
        )
        .await;
        // A consumer domain with a persisted provider that was itself
        // inferred at write time: stays labelled inferred.
        seed(
            format!("msg-{suffix}-inferred"),
            "someone@gmail.com",
            Some("Gmail"),
            Some("inferred"),
        )
        .await;
        // A historical row (pre-migration) with no persisted provider: the
        // suffix fallback labels it inferred.
        seed(
            format!("msg-{suffix}-historical"),
            "legacy@gmail.com",
            None,
            None,
        )
        .await;

        let breakdown =
            provider_breakdown(&pool, Some(&tenant), "30 days", EventColumns::default())
                .await
                .expect("provider breakdown query must execute");

        let mx = breakdown
            .providers
            .iter()
            .find(|p| p.provider == "google_workspace")
            .expect("mx-resolved custom domain must keep its persisted provider");
        assert_eq!(mx.count, 1);
        assert!(!mx.inferred, "mx_resolved is authoritative evidence");

        let inferred_gmail = breakdown
            .providers
            .iter()
            .find(|p| p.provider == "Gmail" && p.inferred)
            .expect("persisted inferred Gmail bucket");
        assert_eq!(inferred_gmail.count, 2, "persisted + historical gmail rows");
        assert!(
            !breakdown.providers.iter().any(|p| p.provider == "Other"),
            "a custom domain with mx evidence must never fall into 'Other': {:?}",
            breakdown.providers
        );

        pool.close().await;
    }

    /// Multi-open on one recipient-send counts once (cohort BOOL_OR), and a
    /// zero-send window yields None rates rather than 0.
    #[tokio::test]
    async fn multi_open_on_one_recipient_send_counts_once() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_cohort_multi_open").await else {
            eprintln!(
                "skipping multi_open_on_one_recipient_send_counts_once: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message = format!("msg-{suffix}");

        for _ in 0..3 {
            seed_event(
                pool.clone(),
                tenant.clone(),
                message.clone(),
                "opened",
                Some("user@example.com"),
                10,
            )
            .await;
        }
        seed_event(
            pool.clone(),
            tenant.clone(),
            message.clone(),
            "sent",
            Some("user@example.com"),
            15,
        )
        .await;

        let counts = send_cohort_counts(&pool, Some(&tenant), "30 days", EventColumns::default())
            .await
            .expect("canonical cohort query must execute");
        assert_eq!(counts.sent, 1);
        assert_eq!(counts.opened, 1, "repeat opens on one cohort count once");

        // A window with no sends at all: rates absent, never 0/inf.
        let empty = send_cohort_counts(&pool, Some(&tenant), "0 days", EventColumns::default())
            .await
            .expect("empty-window cohort query must execute");
        assert_eq!(empty.sent, 0);
        assert_eq!(empty.open_rate(), None);
        assert_eq!(empty.delivery_rate(), None);

        pool.close().await;
    }

    /// Adversarial fallback: on a schema with no persisted provider column,
    /// the consumer-suffix inference runs and is explicitly labelled.
    #[tokio::test]
    async fn provider_breakdown_falls_back_to_labelled_consumer_inference() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_provider_inferred").await else {
            eprintln!(
                "skipping provider_breakdown_falls_back_to_labelled_consumer_inference: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let seed = |message: String, recipient: &'static str| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            async move {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
                     VALUES ($1, $2, $3, 'sent', $4, NOW())",
                )
                .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
                .bind(&tenant)
                .bind(&message)
                .bind(recipient)
                .execute(&pool)
                .await
                .expect("seed sent event");
            }
        };

        // Simulate a pre-migration schema: the persisted dimension does not
        // exist yet, so only consumer suffixes may be classified.
        sqlx::query("ALTER TABLE events DROP COLUMN IF EXISTS recipient_provider")
            .execute(&pool)
            .await
            .expect("drop persisted provider column (throwaway test database)");

        seed(format!("msg-{suffix}-gmail"), "someone@gmail.com").await;
        // A custom domain hosted by Google Workspace must NOT be classified
        // as Gmail from its suffix.
        seed(format!("msg-{suffix}-custom"), "user@acme-corp.example").await;

        let breakdown =
            provider_breakdown(&pool, Some(&tenant), "30 days", EventColumns::default())
                .await
                .expect("provider breakdown query must execute");

        assert_eq!(breakdown.source, ProviderSource::InferredFromConsumerDomain);
        assert!(
            breakdown
                .note
                .as_deref()
                .unwrap_or("")
                .contains("not authoritative"),
            "the response must carry the inference caveat"
        );
        assert!(
            breakdown.providers.iter().all(|p| p.inferred),
            "every fallback bucket must be labelled inferred"
        );

        let gmail = breakdown
            .providers
            .iter()
            .find(|p| p.provider == "Gmail")
            .expect("gmail.com must classify as Gmail");
        assert_eq!(gmail.count, 1);
        let other = breakdown
            .providers
            .iter()
            .find(|p| p.provider == "Other")
            .expect("custom domain must land in Other, not a guessed provider");
        assert_eq!(other.count, 1);

        pool.close().await;
    }
}
