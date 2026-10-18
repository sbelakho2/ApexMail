//! Hourly SES account/domain deliverability monitor.
//!
//! The audit found `ses_account_metrics` / `ses_domain_stats` (migration 020)
//! had no writer since `ops-service/src/ses_monitoring.rs` was deleted. This
//! module restores the genuinely supported half of that contract:
//!
//! * `GetAccount` (aws-sdk-sesv2) — sending limits, utilization, sending
//!   enabled, enforcement status and production access, persisted to
//!   `ses_account_metrics` every tick;
//! * `BatchGetMetricData` (VDM namespace) — the account's `SEND`,
//!   `PERMANENT_BOUNCE` and `COMPLAINT` counts for the last closed UTC day.
//!   The bounce/complaint RATES are derived from those counts and compared
//!   with `SES_BOUNCE_RATE_{WARN,CRITICAL}_PCT` /
//!   `SES_COMPLAINT_RATE_{WARN,CRITICAL}_PCT`. On a state transition a
//!   tenant-less `system_alerts` row is inserted (the live alert table).
//! * `GetDomainStatisticsReport` (VDM) — per verified domain, the inbox/spam
//!   raw counts and read rate for the last closed day, upserted into
//!   `ses_domain_stats` (`UNIQUE(domain, start_date, end_date)`).
//!
//! The SES v2 SDK in `Cargo.lock` (1.140.1) exposes all three calls, so no
//! additional AWS crate is needed. `inbox_count` / `spam_count` map to
//! VDM's `VolumeStatistics::inbox_raw_count` / `spam_raw_count`;
//! `inbox_placement_rate` is derived (inbox / (inbox + spam)); `read_rate`
//! is the report's overall read-rate percentage. The report's daily rows do
//! not carry a read rate, which is why the range is the last closed day and
//! the OVERALL rate is stored with it.
//!
//! # Scheduling
//!
//! [`spawn`] is called from the api-server binary only when the deployment
//! selects the SES transport (`EMAIL_TRANSPORT_TYPE` unset/`ses`). Ticks are
//! hourly with a bounded random jitter; tests never start the loop — they
//! call [`run_once`] or the persistence/threshold helpers explicitly.

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_sesv2::types::{BatchGetMetricDataQuery, Metric, MetricDataResult, MetricNamespace};
use aws_sdk_sesv2::Client;
use chrono::{DateTime, NaiveDate, Utc};
use rand::Rng as _;
use sqlx::PgPool;
use tracing::{error, info, warn};

/// Default cadence: once an hour.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Default maximum startup/tick jitter (five minutes).
pub const DEFAULT_MAX_JITTER: Duration = Duration::from_secs(5 * 60);

/// Alert types written to `system_alerts` (tenant-less account alerts).
pub const BOUNCE_ALERT_TYPE: &str = "ses_bounce_rate";
pub const COMPLAINT_ALERT_TYPE: &str = "ses_complaint_rate";

/// Warning/critical rate thresholds, in percent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub bounce_rate_warn_pct: f64,
    pub bounce_rate_critical_pct: f64,
    pub complaint_rate_warn_pct: f64,
    pub complaint_rate_critical_pct: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            bounce_rate_warn_pct: 5.0,
            bounce_rate_critical_pct: 10.0,
            complaint_rate_warn_pct: 0.1,
            complaint_rate_critical_pct: 0.5,
        }
    }
}

impl Thresholds {
    /// Read the four env vars with the documented safe defaults. A malformed
    /// value, a non-positive value, or a warning threshold at/above its
    /// critical threshold falls back to the WHOLE default set (a threshold
    /// pair that can never escalate is worse than the default).
    pub fn from_env() -> Self {
        Self::from_raw(
            std::env::var("SES_BOUNCE_RATE_WARN_PCT").ok().as_deref(),
            std::env::var("SES_BOUNCE_RATE_CRITICAL_PCT")
                .ok()
                .as_deref(),
            std::env::var("SES_COMPLAINT_RATE_WARN_PCT").ok().as_deref(),
            std::env::var("SES_COMPLAINT_RATE_CRITICAL_PCT")
                .ok()
                .as_deref(),
        )
    }

    /// Pure parser (env values in, validated thresholds out).
    pub fn from_raw(
        bounce_warn: Option<&str>,
        bounce_critical: Option<&str>,
        complaint_warn: Option<&str>,
        complaint_critical: Option<&str>,
    ) -> Self {
        let defaults = Self::default();
        let parse = |raw: Option<&str>, fallback: f64| -> f64 {
            raw.and_then(|value| value.trim().parse::<f64>().ok())
                .filter(|value| value.is_finite() && *value > 0.0)
                .unwrap_or(fallback)
        };
        let parsed = Self {
            bounce_rate_warn_pct: parse(bounce_warn, defaults.bounce_rate_warn_pct),
            bounce_rate_critical_pct: parse(bounce_critical, defaults.bounce_rate_critical_pct),
            complaint_rate_warn_pct: parse(complaint_warn, defaults.complaint_rate_warn_pct),
            complaint_rate_critical_pct: parse(
                complaint_critical,
                defaults.complaint_rate_critical_pct,
            ),
        };
        if parsed.bounce_rate_warn_pct >= parsed.bounce_rate_critical_pct
            || parsed.complaint_rate_warn_pct >= parsed.complaint_rate_critical_pct
        {
            return defaults;
        }
        parsed
    }
}

/// Alert severity (matches the `system_alerts.severity` CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Classify a rate against one warning/critical pair. `None` (no data) can
/// never breach.
pub fn severity_for(rate: Option<f64>, warn: f64, critical: f64) -> Option<Severity> {
    let rate = rate?;
    if rate >= critical {
        Some(Severity::Critical)
    } else if rate >= warn {
        Some(Severity::Warning)
    } else {
        None
    }
}

/// True only when the metric ENTERS (or escalates into) a breached state.
/// Staying breached at the same severity emits nothing; recovery emits
/// nothing (the state is simply cleared).
pub fn should_emit(previous: Option<Severity>, current: Option<Severity>) -> bool {
    current.is_some() && current != previous
}

/// Utilization of the 24-hour send quota, in percent. SES reports `-1` for
/// an unlimited quota; that (and any non-positive/unusable limit) is 0 %.
pub fn utilization_pct(sent_24h: f64, max_24h: f64) -> f64 {
    if !max_24h.is_finite() || max_24h <= 0.0 {
        return 0.0;
    }
    let sent = if sent_24h.is_finite() {
        sent_24h.max(0.0)
    } else {
        0.0
    };
    sent / max_24h * 100.0
}

/// `numerator / denominator` as a percentage; `None` when there is no
/// denominator (no sends → no meaningful rate).
pub fn rate_pct(numerator: i64, denominator: i64) -> Option<f64> {
    if denominator <= 0 {
        return None;
    }
    Some(numerator.max(0) as f64 / denominator as f64 * 100.0)
}

/// Inbox placement percentage from raw inbox/spam counts.
pub fn inbox_placement_pct(inbox: i64, spam: i64) -> Option<f64> {
    let total = inbox.max(0) + spam.max(0);
    if total <= 0 {
        None
    } else {
        Some(inbox.max(0) as f64 / total as f64 * 100.0)
    }
}

/// Sum every value of one VDM result. `None` when the query produced no
/// values (the metric was not returned).
pub fn sum_values(values: &[i64]) -> Option<i64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum())
    }
}

fn sum_metric(results: &[MetricDataResult], id: &str) -> Option<i64> {
    results
        .iter()
        .find(|result| result.id() == Some(id))
        .and_then(|result| sum_values(result.values()))
}

/// The last closed UTC day `[start, end)`.
pub fn report_window(now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let today = now.date_naive();
    let start = today
        .and_hms_opt(0, 0, 0)
        .expect("midnight is a valid time")
        .and_utc()
        - chrono::Duration::days(1);
    let end = start + chrono::Duration::days(1);
    (start, end)
}

/// Account snapshot persisted to `ses_account_metrics`.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountSnapshot {
    pub region: String,
    pub max_24h_send: f64,
    pub sent_24h: f64,
    pub max_send_rate: f64,
    pub sending_enabled: bool,
    pub enforcement_status: String,
    pub production_access: bool,
}

impl AccountSnapshot {
    pub fn utilization_pct(&self) -> f64 {
        utilization_pct(self.sent_24h, self.max_24h_send)
    }
}

/// Persist one account snapshot.
pub async fn persist_account_metrics(
    db: &PgPool,
    snapshot: &AccountSnapshot,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ses_account_metrics
           (region, max_24h_send, sent_24h, max_send_rate, utilization_pct,
            sending_enabled, enforcement_status, production_access, recorded_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())",
    )
    .bind(&snapshot.region)
    .bind(snapshot.max_24h_send)
    .bind(snapshot.sent_24h)
    .bind(snapshot.max_send_rate)
    .bind(snapshot.utilization_pct())
    .bind(snapshot.sending_enabled)
    .bind(&snapshot.enforcement_status)
    .bind(snapshot.production_access)
    .execute(db)
    .await?;
    Ok(())
}

/// Upsert one domain-day row (re-running a tick is idempotent).
#[allow(clippy::too_many_arguments)]
pub async fn persist_domain_stats(
    db: &PgPool,
    domain: &str,
    day: NaiveDate,
    inbox_count: i64,
    spam_count: i64,
    read_rate: Option<f64>,
    inbox_placement_rate: Option<f64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ses_domain_stats
           (domain, start_date, end_date, inbox_count, spam_count,
            read_rate, inbox_placement_rate, recorded_at)
         VALUES ($1, $2::date, $2::date, $3, $4, $5, $6, NOW())
         ON CONFLICT (domain, start_date, end_date) DO UPDATE SET
           inbox_count = EXCLUDED.inbox_count,
           spam_count = EXCLUDED.spam_count,
           read_rate = EXCLUDED.read_rate,
           inbox_placement_rate = EXCLUDED.inbox_placement_rate,
           recorded_at = NOW()",
    )
    .bind(domain)
    .bind(day)
    .bind(inbox_count.max(0))
    .bind(spam_count.max(0))
    .bind(read_rate)
    .bind(inbox_placement_rate)
    .execute(db)
    .await?;
    Ok(())
}

/// Per-process alert transition memory.
#[derive(Debug, Default)]
pub struct AlertState {
    last: HashMap<&'static str, Option<Severity>>,
}

/// Evaluate one rate and insert at most one `system_alerts` row per state
/// transition. The latest stored alert of the same type is also consulted so
/// a process restart during an ongoing breach does not duplicate the row.
async fn check_threshold(
    db: &PgPool,
    state: &mut AlertState,
    key: &'static str,
    alert_type: &'static str,
    label: &str,
    rate: Option<f64>,
    warn_pct: f64,
    critical_pct: f64,
) -> Result<(), sqlx::Error> {
    let current = severity_for(rate, warn_pct, critical_pct);
    let previous = state.last.get(key).copied().flatten();
    if !should_emit(previous, current) {
        state.last.insert(key, current);
        return Ok(());
    }
    let severity = current.expect("should_emit is only true for Some(severity)");
    let threshold = match severity {
        Severity::Warning => warn_pct,
        Severity::Critical => critical_pct,
    };
    let rate = rate.unwrap_or_default();

    let last_stored: Option<String> = sqlx::query_scalar(
        "SELECT severity FROM system_alerts
         WHERE alert_type = $1
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(alert_type)
    .fetch_optional(db)
    .await?;

    if last_stored.as_deref() != Some(severity.as_str()) {
        let message = format!(
            "SES {label} rate {rate:.3}% reached the {} threshold ({threshold:.3}%).",
            severity.as_str()
        );
        sqlx::query(
            "INSERT INTO system_alerts (alert_type, message, severity)
             VALUES ($1, $2, $3)",
        )
        .bind(alert_type)
        .bind(&message)
        .bind(severity.as_str())
        .execute(db)
        .await?;
        info!(
            alert_type,
            severity = severity.as_str(),
            rate,
            threshold,
            "SES deliverability threshold breached"
        );
    }
    state.last.insert(key, current);
    Ok(())
}

/// One monitor tick. Public for tests and an operator-triggered run.
pub async fn run_once(
    db: &PgPool,
    client: &Client,
    region: &str,
    thresholds: Thresholds,
    alert_state: &mut AlertState,
) -> Result<(), String> {
    let account = client
        .get_account()
        .send()
        .await
        .map_err(|error| format!("SES GetAccount failed: {error}"))?;
    let quota = account.send_quota();
    let snapshot = AccountSnapshot {
        region: region.to_string(),
        max_24h_send: quota
            .map(|quota| quota.max24_hour_send())
            .unwrap_or_default(),
        sent_24h: quota
            .map(|quota| quota.sent_last24_hours())
            .unwrap_or_default(),
        max_send_rate: quota.map(|quota| quota.max_send_rate()).unwrap_or_default(),
        sending_enabled: account.sending_enabled(),
        enforcement_status: account
            .enforcement_status()
            .unwrap_or("HEALTHY")
            .to_string(),
        production_access: account.production_access_enabled(),
    };
    persist_account_metrics(db, &snapshot)
        .await
        .map_err(|error| format!("persist ses_account_metrics: {error}"))?;
    info!(
        region,
        utilization_pct = snapshot.utilization_pct(),
        sending_enabled = snapshot.sending_enabled,
        enforcement_status = %snapshot.enforcement_status,
        "SES account snapshot recorded"
    );

    if !snapshot.sending_enabled || snapshot.enforcement_status != "HEALTHY" {
        warn!(
            region,
            sending_enabled = snapshot.sending_enabled,
            enforcement_status = %snapshot.enforcement_status,
            "SES account is not healthy"
        );
    }

    let (start, end) = report_window(Utc::now());
    let start_secs = start.timestamp();
    let end_secs = end.timestamp();
    let query = |id: &str, metric: Metric| {
        BatchGetMetricDataQuery::builder()
            .id(id)
            .namespace(MetricNamespace::Vdm)
            .metric(metric)
            .start_date(aws_sdk_sesv2::primitives::DateTime::from_secs(start_secs))
            .end_date(aws_sdk_sesv2::primitives::DateTime::from_secs(end_secs))
            .build()
            .expect("all batch query fields are set")
    };

    match client
        .batch_get_metric_data()
        .queries(query("send", Metric::Send))
        .queries(query("permanent_bounce", Metric::PermanentBounce))
        .queries(query("complaint", Metric::Complaint))
        .send()
        .await
    {
        Ok(output) => {
            for error in output.errors() {
                warn!(
                    error_code = ?error.code(),
                    message = ?error.message(),
                    "SES VDM metric query returned an error"
                );
            }
            let sends = sum_metric(output.results(), "send");
            let bounces = sum_metric(output.results(), "permanent_bounce");
            let complaints = sum_metric(output.results(), "complaint");
            let bounce_rate =
                sends.and_then(|sends| bounces.and_then(|bounces| rate_pct(bounces, sends)));
            let complaint_rate = sends
                .and_then(|sends| complaints.and_then(|complaints| rate_pct(complaints, sends)));
            info!(
                sends = sends.unwrap_or(0),
                permanent_bounces = bounces.unwrap_or(0),
                complaints = complaints.unwrap_or(0),
                bounce_rate_pct = ?bounce_rate,
                complaint_rate_pct = ?complaint_rate,
                "SES account deliverability metrics recorded"
            );

            if let Err(error) = check_threshold(
                db,
                alert_state,
                BOUNCE_ALERT_TYPE,
                BOUNCE_ALERT_TYPE,
                "bounce",
                bounce_rate,
                thresholds.bounce_rate_warn_pct,
                thresholds.bounce_rate_critical_pct,
            )
            .await
            {
                error!(%error, "failed to record SES bounce-rate alert");
            }
            if let Err(error) = check_threshold(
                db,
                alert_state,
                COMPLAINT_ALERT_TYPE,
                COMPLAINT_ALERT_TYPE,
                "complaint",
                complaint_rate,
                thresholds.complaint_rate_warn_pct,
                thresholds.complaint_rate_critical_pct,
            )
            .await
            {
                error!(%error, "failed to record SES complaint-rate alert");
            }
        }
        Err(error) => {
            // Metrics access can be unavailable (VDM not enabled for the
            // account). The account snapshot above is still recorded; the
            // threshold state is left untouched so a transient API failure
            // cannot manufacture a recovery.
            warn!(%error, "SES VDM metric query failed; thresholds not evaluated this tick");
        }
    }

    record_domain_stats(db, client, start, end).await;
    Ok(())
}

/// Persist the last closed day's VDM stats for every SES-verified domain.
/// Failures are per-domain and never abort the tick.
async fn record_domain_stats(
    db: &PgPool,
    client: &Client,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) {
    let domains: Vec<String> = match sqlx::query_scalar(
        "SELECT name FROM domains WHERE ses_verified = TRUE ORDER BY name LIMIT 500",
    )
    .fetch_all(db)
    .await
    {
        Ok(domains) => domains,
        Err(error) => {
            warn!(%error, "failed to list SES-verified domains; skipping domain statistics");
            return;
        }
    };
    let day = start.date_naive();
    for domain in domains {
        let report = client
            .get_domain_statistics_report()
            .domain(&domain)
            .start_date(aws_sdk_sesv2::primitives::DateTime::from_secs(
                start.timestamp(),
            ))
            .end_date(aws_sdk_sesv2::primitives::DateTime::from_secs(
                end.timestamp(),
            ))
            .send()
            .await;
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                warn!(%error, %domain, "SES domain statistics query failed");
                continue;
            }
        };

        let mut inbox = 0i64;
        let mut spam = 0i64;
        let mut read_rate = None;
        if let Some(overall) = report.overall_volume() {
            read_rate = overall.read_rate_percent();
            if let Some(volume) = overall.volume_statistics() {
                inbox = volume.inbox_raw_count().unwrap_or(0);
                spam = volume.spam_raw_count().unwrap_or(0);
            }
        }
        if inbox == 0 && spam == 0 {
            // A report may carry per-day rows without the overall object.
            for daily in report.daily_volumes() {
                if let Some(volume) = daily.volume_statistics() {
                    inbox += volume.inbox_raw_count().unwrap_or(0);
                    spam += volume.spam_raw_count().unwrap_or(0);
                }
            }
        }
        if inbox == 0 && spam == 0 && read_rate.is_none() {
            continue; // no measured data for this domain/day
        }
        if let Err(error) = persist_domain_stats(
            db,
            &domain,
            day,
            inbox,
            spam,
            read_rate,
            inbox_placement_pct(inbox, spam),
        )
        .await
        {
            error!(%error, %domain, "failed to persist SES domain statistics");
        }
    }
}

/// Scheduling knobs. Tests construct the monitor explicitly; the production
/// binary calls [`spawn`] only when the SES transport is configured.
#[derive(Debug, Clone, Copy)]
pub struct MonitorConfig {
    pub interval: Duration,
    pub max_jitter: Duration,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            max_jitter: DEFAULT_MAX_JITTER,
        }
    }
}

/// Spawn the hourly, jittered monitor. The returned handle can be aborted on
/// shutdown; a failed tick is logged and the next tick retries.
pub fn spawn(
    db: PgPool,
    client: Client,
    region: String,
    thresholds: Thresholds,
    config: MonitorConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut alert_state = AlertState::default();
        loop {
            let jitter_ms = if config.max_jitter.is_zero() {
                0
            } else {
                rand::rng().random_range(
                    0..=u64::try_from(config.max_jitter.as_millis()).unwrap_or(u64::MAX),
                )
            };
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
            match run_once(&db, &client, &region, thresholds, &mut alert_state).await {
                Ok(()) => {}
                Err(error) => error!(%error, "SES deliverability monitor tick failed"),
            }
            tokio::time::sleep(config.interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use migrator::test_support::fresh_canonical_pool;

    async fn test_pool(name: &str) -> Option<PgPool> {
        match fresh_canonical_pool(name, name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    #[test]
    fn thresholds_default_when_unset_or_malformed() {
        let defaults = Thresholds::default();
        assert_eq!(defaults.bounce_rate_warn_pct, 5.0);
        assert_eq!(defaults.bounce_rate_critical_pct, 10.0);
        assert_eq!(defaults.complaint_rate_warn_pct, 0.1);
        assert_eq!(defaults.complaint_rate_critical_pct, 0.5);

        assert_eq!(Thresholds::from_raw(None, None, None, None), defaults);
        assert_eq!(
            Thresholds::from_raw(Some("nope"), Some("-1"), Some("NaN"), Some("0")),
            defaults
        );
        // warn >= critical invalidates the whole set (an escalation that can
        // never happen is not a threshold).
        assert_eq!(
            Thresholds::from_raw(Some("10"), Some("10"), Some("0.1"), Some("0.5")),
            defaults
        );
        assert_eq!(
            Thresholds::from_raw(Some("5"), Some("10"), Some("0.5"), Some("0.1")),
            defaults
        );
        assert_eq!(
            Thresholds::from_raw(Some("4"), Some("8"), Some("0.2"), Some("0.4")),
            Thresholds {
                bounce_rate_warn_pct: 4.0,
                bounce_rate_critical_pct: 8.0,
                complaint_rate_warn_pct: 0.2,
                complaint_rate_critical_pct: 0.4,
            }
        );
        // Surrounding whitespace is accepted.
        assert_eq!(
            Thresholds::from_raw(Some(" 5 "), Some(" 10 "), Some(" 0.1 "), Some(" 0.5 ")),
            defaults
        );
    }

    #[test]
    fn severity_boundaries_are_inclusive() {
        assert_eq!(severity_for(None, 5.0, 10.0), None);
        assert_eq!(severity_for(Some(4.999), 5.0, 10.0), None);
        assert_eq!(severity_for(Some(5.0), 5.0, 10.0), Some(Severity::Warning));
        assert_eq!(
            severity_for(Some(9.999), 5.0, 10.0),
            Some(Severity::Warning)
        );
        assert_eq!(
            severity_for(Some(10.0), 5.0, 10.0),
            Some(Severity::Critical)
        );
        assert_eq!(
            severity_for(Some(99.0), 5.0, 10.0),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn alerts_only_on_transitions_into_a_breach() {
        use Severity::{Critical, Warning};
        assert!(!should_emit(None, None));
        assert!(should_emit(None, Some(Warning)));
        assert!(should_emit(None, Some(Critical)));
        assert!(!should_emit(Some(Warning), Some(Warning)));
        assert!(should_emit(Some(Warning), Some(Critical)));
        assert!(should_emit(Some(Critical), Some(Warning)));
        assert!(!should_emit(Some(Warning), None));
        assert!(!should_emit(Some(Critical), None));
    }

    #[test]
    fn utilization_handles_unlimited_and_unusable_quota() {
        assert_eq!(utilization_pct(50.0, 200.0), 25.0);
        assert_eq!(utilization_pct(0.0, 200.0), 0.0);
        assert_eq!(utilization_pct(1.0, -1.0), 0.0, "SES -1 = unlimited");
        assert_eq!(utilization_pct(1.0, 0.0), 0.0);
        assert_eq!(utilization_pct(1.0, f64::NAN), 0.0);
        assert_eq!(utilization_pct(-5.0, 100.0), 0.0);
    }

    #[test]
    fn rates_and_placement_need_a_denominator() {
        assert_eq!(rate_pct(0, 0), None);
        assert_eq!(rate_pct(10, 100), Some(10.0));
        assert!((rate_pct(1, 3).expect("rate") - 100.0 / 3.0).abs() < 1e-9);
        assert_eq!(rate_pct(-1, 100), Some(0.0));
        assert_eq!(inbox_placement_pct(0, 0), None);
        assert_eq!(inbox_placement_pct(90, 10), Some(90.0));
        assert!((inbox_placement_pct(1, 2).expect("placement") - 100.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn sum_values_is_none_for_an_empty_result() {
        assert_eq!(sum_values(&[]), None);
        assert_eq!(sum_values(&[1]), Some(1));
        assert_eq!(sum_values(&[1, 2, 3]), Some(6));
        assert_eq!(sum_values(&[-1, 1]), Some(0));
    }

    #[test]
    fn report_window_is_the_last_closed_utc_day() {
        let now = DateTime::parse_from_rfc3339("2026-10-18T12:34:56Z")
            .expect("fixed now")
            .with_timezone(&Utc);
        let (start, end) = report_window(now);
        assert_eq!(start.to_rfc3339(), "2026-10-17T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-10-18T00:00:00+00:00");
        assert_eq!(end - start, chrono::Duration::days(1));
    }

    #[tokio::test]
    async fn account_snapshot_persists_utilization_and_flags() {
        let Some(pool) = test_pool("ses_monitor_account").await else {
            return;
        };
        let snapshot = AccountSnapshot {
            region: "eu-west-1".into(),
            max_24h_send: 200.0,
            sent_24h: 50.0,
            max_send_rate: 14.0,
            sending_enabled: true,
            enforcement_status: "HEALTHY".into(),
            production_access: true,
        };
        persist_account_metrics(&pool, &snapshot)
            .await
            .expect("persist");
        let row: (String, f64, f64, f64, f64, bool, String, bool) = sqlx::query_as(
            "SELECT region, max_24h_send, sent_24h, max_send_rate, utilization_pct,
                    sending_enabled, enforcement_status, production_access
             FROM ses_account_metrics",
        )
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(row.0, "eu-west-1");
        assert_eq!(row.1, 200.0);
        assert_eq!(row.2, 50.0);
        assert_eq!(row.3, 14.0);
        assert_eq!(row.4, 25.0);
        assert!(row.5);
        assert_eq!(row.6, "HEALTHY");
        assert!(row.7);
    }

    #[tokio::test]
    async fn domain_stats_upsert_is_idempotent_per_day() {
        let Some(pool) = test_pool("ses_monitor_domain_upsert").await else {
            return;
        };
        let day = NaiveDate::from_ymd_opt(2026, 10, 17).expect("day");
        persist_domain_stats(&pool, "example.com", day, 90, 10, Some(42.0), Some(90.0))
            .await
            .expect("first");
        persist_domain_stats(&pool, "example.com", day, 80, 20, Some(40.0), Some(80.0))
            .await
            .expect("second");
        let rows: Vec<(i64, i64, Option<f64>, Option<f64>)> = sqlx::query_as(
            "SELECT inbox_count, spam_count, read_rate, inbox_placement_rate
             FROM ses_domain_stats WHERE domain = 'example.com'",
        )
        .fetch_all(&pool)
        .await
        .expect("rows");
        assert_eq!(rows.len(), 1, "same (domain, day) upserts");
        assert_eq!(rows[0], (80, 20, Some(40.0), Some(80.0)));
    }

    #[tokio::test]
    async fn threshold_alerts_are_emitted_once_per_transition() {
        let Some(pool) = test_pool("ses_monitor_transitions").await else {
            return;
        };
        let mut state = AlertState::default();
        let alert_count = || async {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM system_alerts WHERE alert_type = $1")
                .bind(BOUNCE_ALERT_TYPE)
                .fetch_one(&pool)
                .await
                .expect("count")
        };

        // First breach: one warning row.
        check_threshold(
            &pool,
            &mut state,
            BOUNCE_ALERT_TYPE,
            BOUNCE_ALERT_TYPE,
            "bounce",
            Some(6.0),
            5.0,
            10.0,
        )
        .await
        .expect("warning");
        assert_eq!(alert_count().await, 1);

        // Same state again: no duplicate.
        check_threshold(
            &pool,
            &mut state,
            BOUNCE_ALERT_TYPE,
            BOUNCE_ALERT_TYPE,
            "bounce",
            Some(7.0),
            5.0,
            10.0,
        )
        .await
        .expect("still warning");
        assert_eq!(alert_count().await, 1);

        // Escalation: one critical row.
        check_threshold(
            &pool,
            &mut state,
            BOUNCE_ALERT_TYPE,
            BOUNCE_ALERT_TYPE,
            "bounce",
            Some(11.0),
            5.0,
            10.0,
        )
        .await
        .expect("critical");
        assert_eq!(alert_count().await, 2);

        // Recovery emits nothing but clears the state.
        check_threshold(
            &pool,
            &mut state,
            BOUNCE_ALERT_TYPE,
            BOUNCE_ALERT_TYPE,
            "bounce",
            Some(1.0),
            5.0,
            10.0,
        )
        .await
        .expect("recovery");
        assert_eq!(alert_count().await, 2);

        // A new breach after recovery alerts again (critical → warning is a
        // new transition tracked in-process).
        check_threshold(
            &pool,
            &mut state,
            BOUNCE_ALERT_TYPE,
            BOUNCE_ALERT_TYPE,
            "bounce",
            Some(6.0),
            5.0,
            10.0,
        )
        .await
        .expect("breach again");
        assert_eq!(alert_count().await, 3);
        let severity: String = sqlx::query_scalar(
            "SELECT severity FROM system_alerts WHERE alert_type = $1
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(BOUNCE_ALERT_TYPE)
        .fetch_one(&pool)
        .await
        .expect("severity");
        assert_eq!(severity, "warning");
    }
}
