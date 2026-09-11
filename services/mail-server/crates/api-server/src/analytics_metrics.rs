//! Canonical analytics metric definitions — ONE source of truth for the
//! business metrics shared by the admin analytics endpoints (and available
//! to the CP SSR loaders through [`distinct_message_counts`]).
//!
//! Conventions applied everywhere in this module:
//!
//! * **Cohort time = event occurrence.** Every metric is bucketed by
//!   `events.timestamp` — the moment the event actually happened. The
//!   `messages.created_at` row-creation timestamp is NEVER used as a proxy
//!   for a send.
//! * **`sent` = a successful send event.** `events.event_type = 'sent'` is
//!   written by the worker only after provider acceptance; a message row
//!   that merely exists is not "sent".
//! * **Cardinality = distinct message ids.** Every count is
//!   `COUNT(DISTINCT message_id)`: multiple opens/clicks of one message (or
//!   per-recipient copies of one send) never inflate a numerator. Ratios are
//!   therefore ≤ 1 by construction — they are never clamped.
//! * **Rates are fractions in `0.0..=1.0`**, never percentages.
//!
//! Schema evidence for every referenced column lives in
//! `services/mail-server/migrations/` (see the doc comments on each query
//! builder below).

use serde::Serialize;
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

/// Distinct-message counts for every metric the engagement surfaces report.
///
/// This is the canonical cardinality contract: one message contributes at
/// most 1 to each count no matter how many opens/clicks/send copies it
/// generated. All rates derived from this struct are therefore in
/// `0.0..=1.0` without clamping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DistinctMessageCounts {
    /// Distinct messages with at least one successful `sent` event.
    pub sent: i64,
    /// Distinct messages with at least one `delivered` event.
    pub delivered: i64,
    /// Distinct messages with at least one `opened` event (repeat opens do
    /// not add).
    pub opened: i64,
    /// Distinct messages with at least one `clicked` event.
    pub clicked: i64,
    /// Distinct messages with at least one `bounced` event.
    pub bounced: i64,
    /// Distinct messages with at least one `complained` event.
    pub complained: i64,
}

impl DistinctMessageCounts {
    /// Fraction of the distinct sent population, in `0.0..=1.0`. Zero sends
    /// yields `0.0` (an explicit empty population, not a fabricated rate).
    /// Because every numerator counts distinct message ids that also had a
    /// send event, the result cannot exceed 1.0 by construction.
    pub fn rate_of_sent(&self, numerator: i64) -> f64 {
        if self.sent > 0 {
            numerator as f64 / self.sent as f64
        } else {
            0.0
        }
    }

    pub fn delivery_rate(&self) -> f64 {
        self.rate_of_sent(self.delivered)
    }

    pub fn open_rate(&self) -> f64 {
        self.rate_of_sent(self.opened)
    }

    pub fn click_rate(&self) -> f64 {
        self.rate_of_sent(self.clicked)
    }

    pub fn bounce_rate(&self) -> f64 {
        self.rate_of_sent(self.bounced)
    }

    pub fn complaint_rate(&self) -> f64 {
        self.rate_of_sent(self.complained)
    }
}

/// One day of distinct-message engagement counts.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DistinctTimeSeriesPoint {
    pub date: String,
    pub sent: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
}

/// The canonical SELECT projection shared by every distinct-message count
/// query: one DISTINCT-message FILTER per metric.
///
/// Columns: `events.message_id` / `event_type` / `timestamp` /
/// `tenant_id` — migration `075_create_missing_tables.sql:30-47`.
fn distinct_counts_select(columns: EventColumns) -> String {
    let type_col = columns.type_col.as_sql();

    format!(
        "SELECT
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'sent') as sent,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'delivered') as delivered,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'opened') as opened,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'clicked') as clicked,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'bounced') as bounced,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'complained') as complained
         FROM events"
    )
}

/// Canonical aggregate query with the window inlined (enum-owned, never user
/// input). `$1` = tenant id (NULL = fleet-wide). Callers with a free-form
/// window use [`distinct_message_counts`], which binds the interval instead.
pub fn distinct_counts_sql(columns: EventColumns, range: AnalyticsRange) -> String {
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
        "{} WHERE {time_col} >= NOW() - '{interval}'::interval \
         AND ($1::text IS NULL OR tenant_id = $1)",
        distinct_counts_select(columns)
    )
}

/// Canonical time-series query: distinct message ids per event type and day,
/// bucketed by event occurrence.
///
/// `$1` = window interval, `$2` = tenant id (NULL = fleet-wide).
pub fn distinct_time_series_sql(columns: EventColumns, range: AnalyticsRange) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
        "SELECT DATE({time_col})::text as d,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'sent') as sent,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'delivered') as delivered,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'opened') as opened,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'clicked') as clicked
         FROM events
         WHERE {time_col} >= NOW() - '{interval}'::interval
           AND ($1::text IS NULL OR tenant_id = $1)
         GROUP BY d ORDER BY d ASC"
    )
}

/// Fetch the canonical distinct-message counts for a window.
///
/// `tenant_id = None` means fleet-wide (system tenant); `Some` scopes to one
/// tenant. `interval` is bound as a parameter (`$1::interval`), so callers
/// can pass any code-owned window string ("24 hours", "30 days", ...).
pub async fn distinct_message_counts(
    db: &PgPool,
    tenant_id: Option<&str>,
    interval: &str,
    columns: EventColumns,
) -> Result<DistinctMessageCounts, ApiError> {
    let time_col = columns.time_col.as_sql();

    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&format!(
        "{} WHERE {time_col} >= NOW() - $1::interval \
         AND ($2::text IS NULL OR tenant_id = $2)",
        distinct_counts_select(columns)
    ))
    .bind(interval)
    .bind(tenant_id)
    .fetch_optional(db)
    .await?
    .unwrap_or((0, 0, 0, 0, 0, 0));

    Ok(DistinctMessageCounts {
        sent: row.0,
        delivered: row.1,
        opened: row.2,
        clicked: row.3,
        bounced: row.4,
        complained: row.5,
    })
}

/// Fetch the canonical counts for the window IMMEDIATELY BEFORE the current
/// one: `[NOW() - 2*interval, NOW() - interval)`. Same cohort/cardinality
/// conventions, so period-over-period comparisons are like-for-like.
pub async fn distinct_message_counts_previous(
    db: &PgPool,
    tenant_id: Option<&str>,
    interval: &str,
    columns: EventColumns,
) -> Result<DistinctMessageCounts, ApiError> {
    let time_col = columns.time_col.as_sql();

    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&format!(
        "{} WHERE {time_col} >= NOW() - $1::interval - $1::interval \
         AND {time_col} < NOW() - $1::interval \
         AND ($2::text IS NULL OR tenant_id = $2)",
        distinct_counts_select(columns)
    ))
    .bind(interval)
    .bind(tenant_id)
    .fetch_optional(db)
    .await?
    .unwrap_or((0, 0, 0, 0, 0, 0));

    Ok(DistinctMessageCounts {
        sent: row.0,
        delivered: row.1,
        opened: row.2,
        clicked: row.3,
        bounced: row.4,
        complained: row.5,
    })
}

/// Fetch the canonical per-day time series for a window.
pub async fn distinct_message_time_series(
    db: &PgPool,
    tenant_id: Option<&str>,
    range: AnalyticsRange,
    columns: EventColumns,
) -> Result<Vec<DistinctTimeSeriesPoint>, ApiError> {
    let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64)>(&distinct_time_series_sql(
        columns, range,
    ))
    .bind(tenant_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(date, sent, delivered, opened, clicked)| DistinctTimeSeriesPoint {
                date,
                sent,
                delivered,
                opened,
                clicked,
            },
        )
        .collect())
}

/// Provider identity source for the sent-event breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSource {
    /// A persisted normalized recipient-provider dimension (`events.<column>`)
    /// was found and used.
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

/// One provider bucket: count of DISTINCT messages sent to that provider.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCount {
    pub provider: String,
    pub count: i64,
    /// `true` when the provider was inferred from the recipient-domain
    /// suffix rather than read from a persisted provider dimension. The UI
    /// must not present inferred buckets as authoritative.
    pub inferred: bool,
}

/// Provider breakdown result plus the provenance needed to label it.
#[derive(Debug, Clone)]
pub struct ProviderBreakdown {
    pub providers: Vec<ProviderCount>,
    pub source: ProviderSource,
    /// Non-empty when the numbers are inferred; callers surface this in the
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

const INFERRED_PROVIDER_NOTE: &str = "Provider identity is inferred from well-known consumer recipient-domain suffixes only; custom domains hosted by Google Workspace / Microsoft 365 and other provider-hosted domains appear as 'Other'. No persisted recipient-provider dimension exists on the events table, so these buckets are not authoritative.";

/// Read the provider breakdown for successfully sent messages.
///
/// Preference order (Fix 2):
/// 1. a persisted normalized provider dimension on `events`
///    (`recipient_provider`, then `provider`) when the schema has one — read
///    it, never re-derive;
/// 2. otherwise classify by recipient-domain suffix for well-known consumer
///    domains ONLY, and label every row `inferred: true` with a response
///    note. Hosted custom domains are never guessed.
pub async fn provider_breakdown(
    db: &PgPool,
    tenant_id: Option<&str>,
    interval: &str,
    columns: EventColumns,
) -> Result<ProviderBreakdown, ApiError> {
    if let Some(column) = detect_column(db, "events", &["recipient_provider", "provider"]).await {
        let type_col = columns.type_col.as_sql();
        let time_col = columns.time_col.as_sql();
        let rows = sqlx::query_as::<_, (String, i64)>(&format!(
            "SELECT COALESCE(NULLIF({column}::text, ''), 'unknown') as provider,
                    COUNT(DISTINCT message_id)::bigint as cnt
             FROM events
             WHERE {time_col} >= NOW() - $1::interval
               AND ($2::text IS NULL OR tenant_id = $2)
               AND {type_col} = 'sent'
             GROUP BY 1 ORDER BY cnt DESC"
        ))
        .bind(interval)
        .bind(tenant_id)
        .fetch_all(db)
        .await?;

        return Ok(ProviderBreakdown {
            providers: rows
                .into_iter()
                .map(|(provider, count)| ProviderCount {
                    provider,
                    count,
                    inferred: false,
                })
                .collect(),
            source: ProviderSource::Persisted,
            note: None,
        });
    }

    // No persisted dimension: consumer-suffix fallback, explicitly inferred.
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let rows = sqlx::query_as::<_, (String, i64)>(&format!(
        "SELECT {CONSUMER_PROVIDER_CASE} as provider,
                COUNT(DISTINCT message_id)::bigint as cnt
         FROM events
         WHERE {time_col} >= NOW() - $1::interval
           AND ($2::text IS NULL OR tenant_id = $2)
           AND {type_col} = 'sent'
         GROUP BY provider ORDER BY cnt DESC"
    ))
    .bind(interval)
    .bind(tenant_id)
    .fetch_all(db)
    .await?;

    Ok(ProviderBreakdown {
        providers: rows
            .into_iter()
            .map(|(provider, count)| ProviderCount {
                provider,
                count,
                inferred: true,
            })
            .collect(),
        source: ProviderSource::InferredFromConsumerDomain,
        note: Some(INFERRED_PROVIDER_NOTE.into()),
    })
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
    fn distinct_counts_sql_counts_distinct_message_ids_only() {
        let sql = distinct_counts_sql(EventColumns::default(), AnalyticsRange::Days30);

        // Every metric is distinct-message based...
        assert_eq!(sql.matches("COUNT(DISTINCT message_id)").count(), 6);
        // ...and there is no raw event-row counting left to inflate a
        // numerator.
        assert!(!sql.contains("COUNT(*)"));
        // Event-occurrence timestamps, not message creation.
        assert!(sql.contains("timestamp >= NOW() - '30 days'::interval"));
        assert!(!sql.contains("created_at"));
    }

    #[test]
    fn distinct_time_series_sql_counts_distinct_message_ids_per_day() {
        let sql = distinct_time_series_sql(EventColumns::default(), AnalyticsRange::Days30);

        assert!(sql.contains("DATE(timestamp)::text"));
        assert!(sql.contains("'30 days'::interval"));
        assert_eq!(sql.matches("COUNT(DISTINCT message_id)").count(), 4);
        assert!(!sql.contains("COUNT(*)"));
    }

    /// Engagement can never exceed 100% once each message counts once — no
    /// clamping required. The old raw-event formulation could produce
    /// opened=300 over sent=100; distinct counts make that state
    /// unrepresentable.
    #[test]
    fn rates_from_distinct_counts_cannot_exceed_one() {
        let counts = DistinctMessageCounts {
            sent: 100,
            delivered: 98,
            opened: 100, // one distinct message opened, 100 total open events
            clicked: 100,
            bounced: 1,
            complained: 0,
        };

        assert!((counts.open_rate() - 1.0).abs() < f64::EPSILON);
        assert!((counts.click_rate() - 1.0).abs() < f64::EPSILON);
        assert!(counts.open_rate() <= 1.0);
        assert!(counts.click_rate() <= 1.0);
        assert!(counts.delivery_rate() <= 1.0);
        assert!(counts.bounce_rate() <= 1.0);
        assert!(counts.complaint_rate() <= 1.0);
    }

    #[test]
    fn zero_send_population_yields_zero_rates_not_a_fabricated_value() {
        let counts = DistinctMessageCounts::default();
        assert_eq!(counts.open_rate(), 0.0);
        assert_eq!(counts.delivery_rate(), 0.0);
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

    /// Fix 1 proof against the canonical schema: three `opened` events on ONE
    /// message must count as ONE opened message, and the engagement ratio
    /// must stay ≤ 100% without clamping. Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn multi_open_on_one_message_does_not_inflate_engagement() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_distinct_msg").await else {
            eprintln!(
                "skipping multi_open_on_one_message_does_not_inflate_engagement: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let msg_open_thrice = format!("msg-{suffix}-a");
        let msg_open_once = format!("msg-{suffix}-b");
        let msg_sent_only = format!("msg-{suffix}-c");

        let seed = |id: String, message: String, event: &'static str| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            async move {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
                     VALUES ($1, $2, $3, $4, 'user@example.com', NOW())",
                )
                .bind(id)
                .bind(&tenant)
                .bind(&message)
                .bind(event)
                .execute(&pool)
                .await
                .expect("seed event");
            }
        };

        for _ in 0..3 {
            seed(
                format!("evt-{}-{}", uuid::Uuid::new_v4().simple(), "o1"),
                msg_open_thrice.clone(),
                "opened",
            )
            .await;
        }
        seed(
            format!("evt-{}", uuid::Uuid::new_v4().simple()),
            msg_open_once.clone(),
            "opened",
        )
        .await;
        // Three successful sends: all three messages.
        for message in [&msg_open_thrice, &msg_open_once, &msg_sent_only] {
            seed(
                format!("evt-{}", uuid::Uuid::new_v4().simple()),
                message.clone(),
                "sent",
            )
            .await;
        }
        seed(
            format!("evt-{}", uuid::Uuid::new_v4().simple()),
            msg_open_thrice.clone(),
            "clicked",
        )
        .await;
        seed(
            format!("evt-{}", uuid::Uuid::new_v4().simple()),
            msg_open_thrice.clone(),
            "clicked",
        )
        .await;

        let counts =
            distinct_message_counts(&pool, Some(&tenant), "30 days", EventColumns::default())
                .await
                .expect("canonical counts query must execute");

        // 3 sent messages, 2 opened messages (NOT 4 open events), 1 clicked
        // message (NOT 2 click events).
        assert_eq!(counts.sent, 3, "one sent event per message");
        assert_eq!(counts.opened, 2, "repeat opens on one message count once");
        assert_eq!(counts.clicked, 1, "repeat clicks on one message count once");

        let open_rate = counts.open_rate();
        assert!(
            open_rate <= 1.0,
            "engagement must be impossible to exceed 100% by construction, got {open_rate}"
        );
        assert!(
            (open_rate - 2.0 / 3.0).abs() < 1e-9,
            "numerator is distinct opened messages (2/3), got {open_rate}"
        );

        // The comparison window immediately before the current one contains
        // none of these (NOW()) events — period-over-period comparisons stay
        // like-for-like on the same cardinality convention.
        let previous = distinct_message_counts_previous(
            &pool,
            Some(&tenant),
            "30 days",
            EventColumns::default(),
        )
        .await
        .expect("previous-window counts query must execute");
        assert_eq!(previous.sent, 0);
        assert_eq!(previous.opened, 0);

        pool.close().await;
    }

    /// Fix 2 proof: with no persisted recipient-provider dimension in the
    /// canonical schema, the breakdown classifies only well-known consumer
    /// domains and labels every bucket `inferred` (custom-domain hosted mail
    /// lands in 'Other' instead of being mislabelled). Gated on
    /// TEST_DATABASE_URL.
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

        seed(format!("msg-{suffix}-gmail"), "someone@gmail.com").await;
        // A custom domain hosted by Google Workspace must NOT be classified
        // as Gmail from its suffix.
        seed(format!("msg-{suffix}-custom"), "user@acme-corp.example").await;

        let breakdown =
            provider_breakdown(&pool, Some(&tenant), "30 days", EventColumns::default())
                .await
                .expect("provider breakdown query must execute");

        // The canonical schema has no recipient-provider column.
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
