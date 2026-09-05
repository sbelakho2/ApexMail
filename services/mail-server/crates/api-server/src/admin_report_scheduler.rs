//! UNWIRED, KNOWN-BUGGY DEAD CODE — do NOT declare in lib.rs.
//!
//! This module is compiled by nothing: `lib.rs` has no
//! `mod admin_report_scheduler;`, and the route module it was written to
//! serve (`routes/admin/reports.rs`) has been deleted (report export is
//! served live by `routes/admin/analytics_export`). It must stay dead until
//! BOTH known defects are fixed:
//!
//! 1. **Duplicate generation** — `should_generate` gates on
//!    `generated_at > now - 1h` per (type, period_start), so after one hour
//!    the same period regenerates on every 30 s tick until the period rolls
//!    over: up to ~2,880 duplicate `report_history` rows per period per
//!    type. There is no unique constraint on
//!    (report_type, period_start) to back an upsert.
//! 2. **numeric→f64 decode** — `collect_metrics` reads
//!    `SUM(CASE ...)` aggregates into `(i64, i64, i64, i64)` via
//!    `query_as`, but untyped `SUM` over INT columns yields NUMERIC, which
//!    sqlx cannot decode into i64 — the query (and therefore every
//!    scheduled report) fails at runtime.
//!
//! Wiring this module without fixing both would produce a scheduler that
//! either floods report_history with duplicates or writes nothing at all.

use chrono::{Datelike, Duration, NaiveDate, NaiveTime, Timelike, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::{interval, MissedTickBehavior};
use tracing;

const SCHEDULE_CHECK_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    Daily,
    Weekly,
    Monthly,
}

impl ReportType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }

    fn scheduled_time_utc(&self) -> NaiveTime {
        match self {
            Self::Daily => NaiveTime::from_hms_opt(0, 5, 0).unwrap(),
            Self::Weekly => NaiveTime::from_hms_opt(0, 10, 0).unwrap(),
            Self::Monthly => NaiveTime::from_hms_opt(0, 15, 0).unwrap(),
        }
    }

    fn period_start(&self, now: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
        let today = now.date_naive();
        match self {
            Self::Daily => today.and_hms_opt(0, 0, 0).unwrap().and_utc(),
            Self::Weekly => {
                let weekday = today.weekday().num_days_from_monday();
                let monday = today - Duration::days(weekday as i64);
                monday.and_hms_opt(0, 0, 0).unwrap().and_utc()
            }
            Self::Monthly => NaiveDate::from_ymd_opt(today.year(), today.month(), 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc(),
        }
    }

    fn period_end(&self, now: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
        match self {
            Self::Daily => self.period_start(now) + Duration::days(1),
            Self::Weekly => self.period_start(now) + Duration::days(7),
            Self::Monthly => {
                let start = self.period_start(now);
                let next_month = if start.month() == 12 {
                    NaiveDate::from_ymd_opt(start.year() + 1, 1, 1)
                } else {
                    NaiveDate::from_ymd_opt(start.year(), start.month() + 1, 1)
                };
                next_month.unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc()
            }
        }
    }
}

#[derive(Debug)]
pub struct ScheduleState {
    pub daily_enabled: AtomicBool,
    pub weekly_enabled: AtomicBool,
    pub monthly_enabled: AtomicBool,
}

impl ScheduleState {
    pub fn new() -> Self {
        Self {
            daily_enabled: AtomicBool::new(true),
            weekly_enabled: AtomicBool::new(true),
            monthly_enabled: AtomicBool::new(true),
        }
    }

    pub fn is_enabled(&self, report_type: ReportType) -> bool {
        match report_type {
            ReportType::Daily => self.daily_enabled.load(Ordering::Relaxed),
            ReportType::Weekly => self.weekly_enabled.load(Ordering::Relaxed),
            ReportType::Monthly => self.monthly_enabled.load(Ordering::Relaxed),
        }
    }

    pub fn set_enabled(&self, report_type: ReportType, enabled: bool) {
        match report_type {
            ReportType::Daily => self.daily_enabled.store(enabled, Ordering::Relaxed),
            ReportType::Weekly => self.weekly_enabled.store(enabled, Ordering::Relaxed),
            ReportType::Monthly => self.monthly_enabled.store(enabled, Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReportSummary {
    pub emails_sent: i64,
    pub emails_delivered: i64,
    pub emails_bounced: i64,
    pub emails_complained: i64,
    pub revenue: f64,
}

pub struct ReportScheduler {
    pub schedule: Arc<ScheduleState>,
    db: PgPool,
    shutdown: Arc<Notify>,
}

impl ReportScheduler {
    pub fn new(db: PgPool, schedule: Arc<ScheduleState>) -> Self {
        Self {
            schedule,
            db,
            shutdown: Arc::new(Notify::new()),
        }
    }

    pub fn start(self: Arc<Self>) {
        let scheduler = self.clone();
        tokio::spawn(async move {
            scheduler.run().await;
        });
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    async fn run(&self) {
        let mut ticker = interval(tokio::time::Duration::from_secs(SCHEDULE_CHECK_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tracing::info!(
            interval_secs = SCHEDULE_CHECK_INTERVAL_SECS,
            "report scheduler started"
        );

        loop {
            tokio::select! {
                _ = self.shutdown.notified() => {
                    tracing::info!("report scheduler shutting down");
                    return;
                }
                _ = ticker.tick() => {
                    self.check_and_generate().await;
                }
            }
        }
    }

    async fn check_and_generate(&self) {
        let now = Utc::now();

        for report_type in &[ReportType::Daily, ReportType::Weekly, ReportType::Monthly] {
            if !self.schedule.is_enabled(*report_type) {
                continue;
            }

            if !self.should_generate(*report_type, now).await {
                continue;
            }

            if let Err(e) = self.generate_report(*report_type).await {
                tracing::error!(
                    report_type = report_type.as_str(),
                    error = %e,
                    "failed to generate scheduled report"
                );
            }
        }
    }

    async fn should_generate(&self, report_type: ReportType, now: chrono::DateTime<Utc>) -> bool {
        let scheduled_time = report_type.scheduled_time_utc();
        let start = report_type.period_start(now);

        if now.time() < scheduled_time {
            return false;
        }

        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM report_history
             WHERE report_type = $1
               AND period_start = $2
               AND generated_at > $3",
        )
        .bind(report_type.as_str())
        .bind(start)
        .bind(now - Duration::hours(1))
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        existing == 0
    }

    async fn generate_report(&self, report_type: ReportType) -> Result<(), anyhow::Error> {
        let now = Utc::now();
        let period_start = report_type.period_start(now);
        let period_end = report_type.period_end(now);

        tracing::info!(
            report_type = report_type.as_str(),
            period_start = %period_start,
            period_end = %period_end,
            "generating scheduled report"
        );

        let summary = self.collect_metrics(period_start, period_end).await?;

        let data = serde_json::to_value(&summary)?;

        sqlx::query(
            "INSERT INTO report_history (report_type, format, period_start, period_end, data)
             VALUES ($1, 'json', $2, $3, $4)",
        )
        .bind(report_type.as_str())
        .bind(period_start)
        .bind(period_end)
        .bind(&data)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    pub async fn collect_metrics(
        &self,
        period_start: chrono::DateTime<Utc>,
        period_end: chrono::DateTime<Utc>,
    ) -> Result<ReportSummary, anyhow::Error> {
        let (sent, delivered, bounced, complained): (i64, i64, i64, i64) =
            sqlx::query_as(
                "SELECT
                    COALESCE(SUM(CASE WHEN event_type = 'send' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN event_type = 'delivery' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN event_type = 'bounce' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN event_type = 'complaint' THEN 1 ELSE 0 END), 0)
                 FROM events
                 WHERE timestamp >= $1 AND timestamp < $2",
            )
            .bind(period_start)
            .bind(period_end)
            .fetch_one(&self.db)
            .await?;

        let revenue: f64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_cents) / 100.0, 0.0)
             FROM invoice_line_items
             WHERE created_at >= $1 AND created_at < $2",
        )
        .bind(period_start)
        .bind(period_end)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0.0);

        Ok(ReportSummary {
            emails_sent: sent,
            emails_delivered: delivered,
            emails_bounced: bounced,
            emails_complained: complained,
            revenue,
        })
    }
}
