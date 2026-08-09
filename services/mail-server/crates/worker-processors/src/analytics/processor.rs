//! Analytics processor implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, TimeDelta, TimeZone, Timelike, Utc};
use sqlx::PgPool;
use std::sync::RwLock;
use tokio::sync::Notify;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

use super::types::{AggregatedStats, AnalyticsEvent};
use crate::common::{AnalyticsConfig, ProcessorResult, RedisPool};

/// Maximum event buffer size to prevent OOM.
const MAX_EVENT_BUFFER_SIZE: usize = 50_000;

/// Maximum aggregation buffer keys before forced eviction.
const MAX_AGGREGATION_BUFFER_SIZE: usize = 10_000;

/// Minimum events in buffer before triggering a flush (even if flush_interval
/// has elapsed). Prevents tiny flushes that waste ClickHouse write throughput.
const MIN_FLUSH_BATCH_SIZE: usize = 50;

/// Analytics processor for event aggregation and real-time stats.
pub struct AnalyticsProcessor {
    db: PgPool,
    redis: RedisPool,
    config: AnalyticsConfig,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    event_buffer: Arc<RwLock<Vec<AnalyticsEvent>>>,
    aggregation_buffer: Arc<RwLock<HashMap<String, AggregatedStats>>>,
    is_flushing: AtomicBool,
    shutdown_notify: Arc<Notify>,
}

impl AnalyticsProcessor {
    /// Create a new analytics processor.
    pub fn new(db: PgPool, redis: RedisPool, config: AnalyticsConfig) -> Self {
        Self {
            db,
            redis,
            config,
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            event_buffer: Arc::new(RwLock::new(Vec::new())),
            aggregation_buffer: Arc::new(RwLock::new(HashMap::new())),
            is_flushing: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            "Starting analytics processor (batch_size={}, flush_interval={:?})",
            self.config.base.batch_size, self.config.base.flush_interval
        );

        self.is_running.store(true, Ordering::SeqCst);

        // Spawn flush task
        let this = Arc::clone(&self);
        tokio::spawn(async move {
            this.flush_loop().await;
        });

        // Spawn hourly aggregation task
        let this = Arc::clone(&self);
        tokio::spawn(async move {
            this.hourly_aggregation_loop().await;
        });

        // Run the poll loop
        self.poll_loop().await;

        Ok(())
    }

    /// Stop the processor gracefully.
    pub async fn stop(&self) -> ProcessorResult<()> {
        info!("Stopping analytics processor");
        self.is_running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Flush remaining buffers
        if let Err(e) = self.flush_buffers().await {
            error!("Error flushing buffers during shutdown: {}", e);
        }

        // Wait for active jobs to complete
        let max_wait = Duration::from_secs(30);
        let start = std::time::Instant::now();

        while self.active_jobs.load(Ordering::SeqCst) > 0 && start.elapsed() < max_wait {
            sleep(Duration::from_millis(100)).await;
        }

        info!("Analytics processor stopped");
        Ok(())
    }

    /// Main poll loop.
    async fn poll_loop(&self) {
        while self.is_running.load(Ordering::SeqCst) {
            match self.poll_batch().await {
                Ok(count) => {
                    if count == 0 {
                        // No events, wait before polling again
                        tokio::select! {
                            _ = sleep(self.config.base.poll_interval) => {}
                            _ = self.shutdown_notify.notified() => break,
                        }
                    }
                }
                Err(e) => {
                    error!("Poll error: {}", e);
                    sleep(self.config.base.poll_interval).await;
                }
            }
        }
    }

    /// Poll and process a batch of events.
    async fn poll_batch(&self) -> ProcessorResult<usize> {
        let events = self.fetch_events(self.config.base.batch_size).await?;
        let count = events.len();

        if count > 0 {
            self.process_events(events).await?;
        }

        Ok(count)
    }

    /// Fetch events from the queue with FOR UPDATE SKIP LOCKED.
    async fn fetch_events(&self, limit: usize) -> ProcessorResult<Vec<AnalyticsEvent>> {
        let events = sqlx::query_as::<_, AnalyticsEvent>(
            r#"
            WITH claimed AS (
                SELECT id
                FROM analytics_queue
                WHERE processed = false AND processing = false
                ORDER BY timestamp ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE analytics_queue
            SET processing = true, processing_at = NOW()
            WHERE id IN (SELECT id FROM claimed)
            RETURNING
                id::text AS id, COALESCE(tenant_id, '') AS tenant_id, event_type,
                message_id, domain_id, campaign_id,
                recipient, metadata, timestamp
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.db)
        .await?;

        Ok(events)
    }

    /// Mark events as fully processed.
    async fn mark_events_processed(&self, event_ids: &[String]) -> ProcessorResult<()> {
        if event_ids.is_empty() {
            return Ok(());
        }

        sqlx::query(
            r#"
            UPDATE analytics_queue
            SET processed = true, processed_at = NOW(), processing = false
            WHERE id = ANY($1::bigint[])
            "#,
        )
        .bind(event_ids)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Reset processing flag for failed events.
    async fn reset_processing(&self, event_ids: &[String]) -> ProcessorResult<()> {
        if event_ids.is_empty() {
            return Ok(());
        }

        sqlx::query(
            r#"
            UPDATE analytics_queue
            SET processing = false, processing_at = NULL
            WHERE id = ANY($1::bigint[])
            "#,
        )
        .bind(event_ids)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Process a batch of events.
    async fn process_events(&self, events: Vec<AnalyticsEvent>) -> ProcessorResult<()> {
        self.active_jobs.fetch_add(1, Ordering::SeqCst);

        let event_ids: Vec<String> = events.iter().map(|e| e.id.clone()).collect();

        let result = self.process_events_inner(events).await;

        self.active_jobs.fetch_sub(1, Ordering::SeqCst);

        if result.is_err() {
            // Reset processing flag for retry
            if let Err(e) = self.reset_processing(&event_ids).await {
                error!("Failed to reset processing flag: {}", e);
            }
        }

        result
    }

    /// Inner processing logic (separated for borrow checker).
    async fn process_events_inner(&self, events: Vec<AnalyticsEvent>) -> ProcessorResult<()> {
        let event_ids: Vec<String> = events.iter().map(|e| e.id.clone()).collect();

        // Add to event buffer (sync operation)
        let should_flush = {
            let mut buffer = self.event_buffer.write().unwrap_or_else(|e| e.into_inner());
            buffer.extend(events.iter().cloned());

            // Enforce buffer size cap
            if buffer.len() > MAX_EVENT_BUFFER_SIZE {
                let dropped = buffer.len() - MAX_EVENT_BUFFER_SIZE;
                buffer.drain(0..dropped);
                warn!(
                    dropped = dropped,
                    cap = MAX_EVENT_BUFFER_SIZE,
                    "Event buffer exceeded cap, dropped oldest events"
                );
            }

            buffer.len() >= self.config.base.batch_size
        };

        // Update aggregation counters (sync operation)
        for event in &events {
            self.update_aggregation(event);
        }

        // Flush if buffer is full (async operation, lock already released)
        if should_flush {
            self.flush_buffers().await?;
        }

        // Mark events as processed
        self.mark_events_processed(&event_ids).await?;

        Ok(())
    }

    /// Update aggregation buffer with an event.
    fn update_aggregation(&self, event: &AnalyticsEvent) {
        let period_start = match Utc.with_ymd_and_hms(
            event.timestamp.year(),
            event.timestamp.month(),
            event.timestamp.day(),
            event.timestamp.hour(),
            0,
            0,
        ) {
            chrono::LocalResult::Single(dt) => dt,
            _ => {
                warn!("Failed to construct period_start from event timestamp, using truncated");
                event
                    .timestamp
                    .date_naive()
                    .and_hms_opt(event.timestamp.hour(), 0, 0)
                    .map(|dt| dt.and_utc())
                    .unwrap_or(event.timestamp)
            }
        };
        let period_end = period_start + TimeDelta::try_hours(1).unwrap_or(TimeDelta::zero());

        // Use epoch milliseconds for period key (no ambiguous ':' characters)
        let period_key = period_start.timestamp_millis().to_string();

        // Generate aggregation keys
        let mut keys: Vec<(String, Option<String>, Option<String>)> =
            vec![(format!("T:{}:{}", event.tenant_id, period_key), None, None)];

        if let Some(domain_id) = &event.domain_id {
            keys.push((
                format!("D:{}:{}:{}", event.tenant_id, domain_id, period_key),
                Some(domain_id.clone()),
                None,
            ));
        }

        if let Some(campaign_id) = &event.campaign_id {
            keys.push((
                format!("C:{}:{}:{}", event.tenant_id, campaign_id, period_key),
                None,
                Some(campaign_id.clone()),
            ));
        }

        if let (Some(domain_id), Some(campaign_id)) = (&event.domain_id, &event.campaign_id) {
            keys.push((
                format!(
                    "DC:{}:{}:{}:{}",
                    event.tenant_id, domain_id, campaign_id, period_key
                ),
                Some(domain_id.clone()),
                Some(campaign_id.clone()),
            ));
        }

        let mut buffer = self
            .aggregation_buffer
            .write()
            .unwrap_or_else(|e| e.into_inner());

        for (key, domain_id, campaign_id) in keys {
            let stats = buffer.entry(key).or_insert_with(|| {
                AggregatedStats::new(
                    event.tenant_id.clone(),
                    domain_id,
                    campaign_id,
                    period_start,
                    period_end,
                )
            });

            stats.increment(&event.event_type);
        }

        if buffer.len() > MAX_AGGREGATION_BUFFER_SIZE {
            let excess = buffer.len() - MAX_AGGREGATION_BUFFER_SIZE;
            let mut keys_by_age: Vec<(String, chrono::DateTime<Utc>)> = buffer
                .iter()
                .map(|(k, v)| (k.clone(), v.period_start))
                .collect();
            keys_by_age.sort_by_key(|(_, ts)| *ts);
            let keys_to_remove: Vec<String> = keys_by_age
                .into_iter()
                .take(excess)
                .map(|(k, _)| k)
                .collect();
            for key in &keys_to_remove {
                buffer.remove(key);
            }
            warn!(
                evicted = excess,
                buffer_size = buffer.len(),
                cap = MAX_AGGREGATION_BUFFER_SIZE,
                "Aggregation buffer exceeded cap, evicted oldest entries by period_start"
            );
        }
    }

    /// Periodic flush loop — flushes when either:
    /// 1. The flush interval has elapsed AND there are MIN_FLUSH_BATCH_SIZE events, OR
    /// 2. The buffer exceeds the configured batch_size (size-based trigger, see process_events_inner).
    ///
    /// This prevents tiny flushes that waste ClickHouse write throughput while still
    /// ensuring timely delivery during low-volume periods.
    async fn flush_loop(&self) {
        let mut flush_interval = interval(self.config.base.flush_interval);
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while self.is_running.load(Ordering::SeqCst) {
            tokio::select! {
                _ = flush_interval.tick() => {
                    // Only flush if the buffer has enough events to justify a batch.
                    let buffer_len = self.event_buffer.read()
                        .map(|b| b.len())
                        .unwrap_or(0);
                    if buffer_len >= MIN_FLUSH_BATCH_SIZE {
                        if let Err(e) = self.flush_buffers().await {
                            error!("Flush error: {}", e);
                        }
                    } else {
                        debug!(
                            buffer_len = buffer_len,
                            min_flush = MIN_FLUSH_BATCH_SIZE,
                            "Skipping flush — buffer below minimum batch size"
                        );
                    }
                }
                _ = self.shutdown_notify.notified() => break,
            }
        }
    }

    /// Flush event and aggregation buffers.
    async fn flush_buffers(&self) -> ProcessorResult<()> {
        // Mutex to prevent concurrent flushes
        if self
            .is_flushing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        let result = self.flush_buffers_inner().await;

        self.is_flushing.store(false, Ordering::SeqCst);

        result
    }

    async fn flush_buffers_inner(&self) -> ProcessorResult<()> {
        let (events, _event_ids): (Vec<AnalyticsEvent>, Vec<String>) = {
            let mut buffer = self.event_buffer.write().unwrap_or_else(|e| e.into_inner());
            let ids: Vec<_> = buffer.iter().map(|e| e.id.clone()).collect();
            let events = std::mem::take(&mut *buffer);
            (events, ids)
        };

        let aggregations: HashMap<String, AggregatedStats> = {
            let mut buffer = self
                .aggregation_buffer
                .write()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *buffer)
        };

        if events.is_empty() && aggregations.is_empty() {
            return Ok(());
        }

        debug!(
            events = events.len(),
            aggregations = aggregations.len(),
            "Flushing analytics buffers"
        );

        // Write aggregations to DB.
        self.write_aggregations(&aggregations).await?;

        // Update Redis counters (failure here won't cause double-counting)
        if let Err(e) = self.update_redis_counters(&events).await {
            // Log but don't fail - Redis counters can be rebuilt from DB
            tracing::warn!(error = %e, "Failed to update Redis counters; will retry on next flush");
        }

        // Event buffer already drained via mem::take above - no need to remove individually.

        debug!(
            events = events.len(),
            aggregations = aggregations.len(),
            "Buffers flushed successfully"
        );

        Ok(())
    }

    /// Write aggregations to analytics_hourly table.
    async fn write_aggregations(
        &self,
        aggregations: &HashMap<String, AggregatedStats>,
    ) -> ProcessorResult<()> {
        if aggregations.is_empty() {
            return Ok(());
        }

        // Batch upsert using unnest
        let mut ids = Vec::with_capacity(aggregations.len());
        let mut tenant_ids = Vec::with_capacity(aggregations.len());
        let mut domain_ids: Vec<Option<String>> = Vec::with_capacity(aggregations.len());
        let mut campaign_ids: Vec<Option<String>> = Vec::with_capacity(aggregations.len());
        let mut period_starts = Vec::with_capacity(aggregations.len());
        let mut period_ends = Vec::with_capacity(aggregations.len());
        let mut sent_arr = Vec::with_capacity(aggregations.len());
        let mut delivered_arr = Vec::with_capacity(aggregations.len());
        let mut opened_arr = Vec::with_capacity(aggregations.len());
        let mut clicked_arr = Vec::with_capacity(aggregations.len());
        let mut bounced_arr = Vec::with_capacity(aggregations.len());
        let mut unsubscribed_arr = Vec::with_capacity(aggregations.len());
        let mut complained_arr = Vec::with_capacity(aggregations.len());
        let mut failed_arr = Vec::with_capacity(aggregations.len());

        for stats in aggregations.values() {
            ids.push(format!("anh_{}", uuid::Uuid::new_v4()));
            tenant_ids.push(stats.tenant_id.clone());
            domain_ids.push(stats.domain_id.clone());
            campaign_ids.push(stats.campaign_id.clone());
            period_starts.push(stats.period_start);
            period_ends.push(stats.period_end);
            sent_arr.push(stats.sent);
            delivered_arr.push(stats.delivered);
            opened_arr.push(stats.opened);
            clicked_arr.push(stats.clicked);
            bounced_arr.push(stats.bounced);
            unsubscribed_arr.push(stats.unsubscribed);
            complained_arr.push(stats.complained);
            failed_arr.push(stats.failed);
        }

        sqlx::query(
            r#"
            INSERT INTO analytics_hourly (
                id, tenant_id, domain_id, campaign_id, period_start, period_end,
                sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
                created_at, updated_at
            )
            SELECT
                unnest($1::text[]),
                unnest($2::text[]),
                unnest($3::text[]),
                unnest($4::text[]),
                unnest($5::timestamptz[]),
                unnest($6::timestamptz[]),
                unnest($7::bigint[]),
                unnest($8::bigint[]),
                unnest($9::bigint[]),
                unnest($10::bigint[]),
                unnest($11::bigint[]),
                unnest($12::bigint[]),
                unnest($13::bigint[]),
                unnest($14::bigint[]),
                NOW(),
                NOW()
            ON CONFLICT (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)
            DO UPDATE SET
                sent = analytics_hourly.sent + EXCLUDED.sent,
                delivered = analytics_hourly.delivered + EXCLUDED.delivered,
                opened = analytics_hourly.opened + EXCLUDED.opened,
                clicked = analytics_hourly.clicked + EXCLUDED.clicked,
                bounced = analytics_hourly.bounced + EXCLUDED.bounced,
                unsubscribed = analytics_hourly.unsubscribed + EXCLUDED.unsubscribed,
                complained = analytics_hourly.complained + EXCLUDED.complained,
                failed = analytics_hourly.failed + EXCLUDED.failed,
                updated_at = NOW()
            "#,
        )
        .bind(&ids)
        .bind(&tenant_ids)
        .bind(&domain_ids)
        .bind(&campaign_ids)
        .bind(&period_starts)
        .bind(&period_ends)
        .bind(&sent_arr)
        .bind(&delivered_arr)
        .bind(&opened_arr)
        .bind(&clicked_arr)
        .bind(&bounced_arr)
        .bind(&unsubscribed_arr)
        .bind(&complained_arr)
        .bind(&failed_arr)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Update real-time counters in Redis.
    async fn update_redis_counters(&self, events: &[AnalyticsEvent]) -> ProcessorResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut conn = self.redis.get().await?;
        let ttl_secs = self.config.stats_ttl.as_secs() as i64;

        // Group events by Redis key
        let mut counters: HashMap<String, i64> = HashMap::new();

        for event in events {
            let date = event.timestamp.format("%Y-%m-%d").to_string();

            // Tenant-level counter
            let key = format!("stats:{}:{}:{}", event.tenant_id, date, event.event_type);
            *counters.entry(key).or_insert(0) += 1;

            // Domain-level counter
            if let Some(domain_id) = &event.domain_id {
                let key = format!(
                    "stats:{}:{}:domain:{}:{}",
                    event.tenant_id, date, domain_id, event.event_type
                );
                *counters.entry(key).or_insert(0) += 1;
            }

            // Campaign-level counter
            if let Some(campaign_id) = &event.campaign_id {
                let key = format!(
                    "stats:{}:{}:campaign:{}:{}",
                    event.tenant_id, date, campaign_id, event.event_type
                );
                *counters.entry(key).or_insert(0) += 1;
            }
        }

        // Execute Redis commands
        let mut pipe = redis::pipe();
        for (key, increment) in &counters {
            pipe.cmd("INCRBY").arg(key).arg(*increment).ignore();
            pipe.cmd("EXPIRE").arg(key).arg(ttl_secs).ignore();
        }

        pipe.query_async::<()>(&mut *conn).await?;

        Ok(())
    }

    /// Hourly aggregation loop (rolls up data from events table).
    async fn hourly_aggregation_loop(&self) {
        // Run at the start of each hour
        while self.is_running.load(Ordering::SeqCst) {
            // Calculate time until next hour
            let now = Utc::now();
            let one_hour = TimeDelta::try_hours(1).unwrap_or(TimeDelta::zero());
            let next_hour = (now + one_hour)
                .with_minute(0)
                .unwrap_or(now + one_hour)
                .with_second(0)
                .unwrap_or(now + one_hour)
                .with_nanosecond(0)
                .unwrap_or(now + one_hour);
            let wait_duration = (next_hour - now)
                .to_std()
                .unwrap_or(Duration::from_secs(3600));

            tokio::select! {
                _ = sleep(wait_duration) => {
                    if let Err(e) = self.run_hourly_aggregation().await {
                        error!("Hourly aggregation error: {}", e);
                    }
                }
                _ = self.shutdown_notify.notified() => break,
            }
        }
    }

    /// Run hourly aggregation from events table.
    async fn run_hourly_aggregation(&self) -> ProcessorResult<()> {
        info!("Running hourly aggregation");

        // Aggregate the previous hour's data
        let prev_hour = Utc::now() - TimeDelta::try_hours(1).unwrap_or(TimeDelta::zero());
        let period_start = match Utc.with_ymd_and_hms(
            prev_hour.year(),
            prev_hour.month(),
            prev_hour.day(),
            prev_hour.hour(),
            0,
            0,
        ) {
            chrono::LocalResult::Single(dt) => dt,
            _ => {
                warn!("Failed to construct hourly period_start, falling back");
                prev_hour
            }
        };
        let period_end = period_start + TimeDelta::try_hours(1).unwrap_or(TimeDelta::zero());

        sqlx::query(
            r#"
            INSERT INTO analytics_hourly (
                id, tenant_id, domain_id, campaign_id, period_start, period_end,
                sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
                created_at, updated_at
            )
            SELECT
                'anh_' || gen_random_uuid(),
                tenant_id,
                domain_id,
                NULL as campaign_id,
                $1,
                $2,
                COUNT(*) FILTER (WHERE event_type = 'sent'),
                COUNT(*) FILTER (WHERE event_type = 'delivered'),
                COUNT(*) FILTER (WHERE event_type = 'opened'),
                COUNT(*) FILTER (WHERE event_type = 'clicked'),
                COUNT(*) FILTER (WHERE event_type = 'bounced'),
                COUNT(*) FILTER (WHERE event_type = 'unsubscribed'),
                COUNT(*) FILTER (WHERE event_type = 'complained'),
                COUNT(*) FILTER (WHERE event_type = 'failed'),
                NOW(),
                NOW()
            FROM events
            WHERE timestamp >= $1 AND timestamp < $2
            GROUP BY tenant_id, domain_id
            ON CONFLICT (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)
            DO UPDATE SET
                sent = EXCLUDED.sent,
                delivered = EXCLUDED.delivered,
                opened = EXCLUDED.opened,
                clicked = EXCLUDED.clicked,
                bounced = EXCLUDED.bounced,
                unsubscribed = EXCLUDED.unsubscribed,
                complained = EXCLUDED.complained,
                failed = EXCLUDED.failed,
                updated_at = NOW()
            "#,
        )
        .bind(period_start)
        .bind(period_end)
        .execute(&self.db)
        .await?;

        info!("Hourly aggregation completed for period {:?}", period_start);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregated_stats_increment() {
        let mut stats = AggregatedStats::default();

        stats.increment("sent");
        stats.increment("sent");
        stats.increment("delivered");
        stats.increment("opened");
        stats.increment("clicked");
        stats.increment("bounced");
        stats.increment("unknown"); // Should be ignored

        assert_eq!(stats.sent, 2);
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.opened, 1);
        assert_eq!(stats.clicked, 1);
        assert_eq!(stats.bounced, 1);
        assert_eq!(stats.failed, 0);
    }
}
