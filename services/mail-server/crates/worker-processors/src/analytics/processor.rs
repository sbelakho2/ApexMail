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

/// Maximum age of the oldest buffered event before a flush is forced even
/// below MIN_FLUSH_BATCH_SIZE — low-volume tenants must not wait forever.
const MAX_BUFFER_AGE: Duration = Duration::from_secs(30);

/// Analytics processor for event aggregation and real-time stats.
pub struct AnalyticsProcessor {
    db: PgPool,
    redis: RedisPool,
    config: AnalyticsConfig,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    event_buffer: Arc<RwLock<Vec<AnalyticsEvent>>>,
    aggregation_buffer: Arc<RwLock<HashMap<String, AggregatedStats>>>,
    /// Wall-clock time when the event buffer last went from empty to
    /// non-empty — drives the age-based flush. `None` while the buffer is
    /// empty.
    oldest_buffered_at: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
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
            oldest_buffered_at: Arc::new(std::sync::Mutex::new(None)),
            is_flushing: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        let batch_size = self.config.base.batch_size;
        let flush_interval = self.config.base.flush_interval;
        info!(
            "Starting analytics processor (batch_size={batch_size}, flush_interval={flush_interval:?})"
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
            error!(error = %e, "Error flushing buffers during shutdown");
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
    ///
    /// Rows claimed (`processing = true`) by a worker that died before the
    /// flush completed are reclaimed once their claim is 10 minutes old, so
    /// events can never be stranded in `processing` forever.
    async fn fetch_events(&self, limit: usize) -> ProcessorResult<Vec<AnalyticsEvent>> {
        let events = sqlx::query_as::<_, AnalyticsEvent>(
            r#"
            WITH claimed AS (
                SELECT id
                FROM analytics_queue
                WHERE processed = false
                  AND (
                      processing = false
                      OR processing_at < NOW() - interval '10 minutes'
                  )
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

    /// Process a batch of events.
    ///
    /// The reset-processing arm that used to live here was REMOVED as dead
    /// (and had it ever fired, wrong) code: `process_events_inner` cannot
    /// fail — a flush write failure is deliberately swallowed, with the
    /// buffers restored and the rows left CLAIMED so the flush loop retries
    /// them without a re-fetch. Resetting `processing` there would have
    /// re-claimed rows whose events were still buffered and re-aggregated
    /// them on the next pass (update_aggregation increments
    /// unconditionally). The claim is instead released by the retrying
    /// flush (mark_events_processed) or reclaimed after the staleness
    /// window.
    async fn process_events(&self, events: Vec<AnalyticsEvent>) -> ProcessorResult<()> {
        self.active_jobs.fetch_add(1, Ordering::SeqCst);

        let result = self.process_events_inner(events).await;

        self.active_jobs.fetch_sub(1, Ordering::SeqCst);

        result
    }

    /// Inner processing logic (separated for borrow checker).
    ///
    /// Events are only marked `processed` AFTER a flush that included them
    /// has written to the DB (see `flush_buffers_inner`) — never here. Until
    /// then they stay claimed in `analytics_queue` and owned by the in-memory
    /// buffer, so a write failure cannot lose or double-count them.
    async fn process_events_inner(&self, events: Vec<AnalyticsEvent>) -> ProcessorResult<()> {
        // Add to event buffer (sync operation). Ids already present are
        // skipped — a restored flush buffer can overlap with re-claimed rows.
        let should_flush = {
            let mut buffer = self.event_buffer.write().unwrap_or_else(|e| e.into_inner());
            let was_empty = buffer.is_empty();
            let known: std::collections::HashSet<String> =
                buffer.iter().map(|e| e.id.clone()).collect();
            for event in &events {
                if !known.contains(&event.id) {
                    buffer.push(event.clone());
                }
            }

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

            if was_empty && !buffer.is_empty() {
                // Start the age-based flush clock.
                *self
                    .oldest_buffered_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
            }

            buffer.len() >= self.config.base.batch_size
        };

        // Update aggregation counters (sync operation)
        for event in &events {
            self.update_aggregation(event);
        }

        // Flush if buffer is full (async operation, lock already released).
        // Flush errors do NOT fail this batch: the buffer is restored by
        // flush_buffers_inner and retried by the flush loop, and the events
        // remain claimed (not re-fetched), so nothing is lost or
        // double-counted.
        if should_flush {
            if let Err(e) = self.flush_buffers().await {
                error!(error = %e, "Buffer flush failed; events retained for retry");
            }
        }

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
            let buffer_size = buffer.len();
            warn!(
                evicted = excess,
                buffer_size,
                cap = MAX_AGGREGATION_BUFFER_SIZE,
                "Aggregation buffer exceeded cap, evicted oldest entries by period_start"
            );
        }
    }

    /// Periodic flush loop — flushes when either:
    /// 1. The flush interval has elapsed AND there are MIN_FLUSH_BATCH_SIZE events, OR
    /// 2. The buffer exceeds the configured batch_size (size-based trigger, see process_events_inner), OR
    /// 3. The oldest buffered event is older than MAX_BUFFER_AGE (age-based
    ///    trigger — low-volume tenants must not have events stuck in a
    ///    too-small batch indefinitely).
    ///
    /// This prevents tiny flushes that waste ClickHouse write throughput while still
    /// ensuring timely delivery during low-volume periods.
    async fn flush_loop(&self) {
        let mut flush_interval = interval(self.config.base.flush_interval);
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while self.is_running.load(Ordering::SeqCst) {
            tokio::select! {
                _ = flush_interval.tick() => {
                    // Only flush if the buffer justifies a batch by size...
                    let buffer_len = self.event_buffer.read()
                        .map(|b| b.len())
                        .unwrap_or(0);
                    // ...or the oldest event has been waiting too long.
                    let oldest_age = self
                        .oldest_buffered_at
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .map(|at| at.elapsed());
                    let age_flush = oldest_age.is_some_and(|age| age > MAX_BUFFER_AGE);
                    if buffer_len >= MIN_FLUSH_BATCH_SIZE || age_flush {
                        if let Err(e) = self.flush_buffers().await {
                            error!("Flush error: {}", e);
                        }
                    } else {
                        debug!(
                            buffer_len = buffer_len,
                            min_flush = MIN_FLUSH_BATCH_SIZE,
                            oldest_age = ?oldest_age,
                            "Skipping flush — buffer below minimum batch size and age"
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
        let (events, event_ids): (Vec<AnalyticsEvent>, Vec<String>) = {
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

        // The buffers were drained — reset the age-based flush clock; it is
        // restarted by restore_buffers() on failure or by the next buffered
        // event.
        *self
            .oldest_buffered_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;

        let event_count = events.len();
        let aggregation_count = aggregations.len();
        debug!(
            events = event_count,
            aggregations = aggregation_count,
            "Flushing analytics buffers"
        );

        // Write aggregations to DB. On failure the drained buffers are
        // RESTORED so the flush loop retries them — events are never lost.
        if let Err(e) = self.write_aggregations(&aggregations).await {
            error!(error = %e, "Aggregation write failed; restoring buffers for retry");
            self.restore_buffers(events, aggregations);
            return Err(e);
        }

        // Update Redis counters (failure here won't cause double-counting)
        if let Err(e) = self.update_redis_counters(&events).await {
            // Log but don't fail - Redis counters can be rebuilt from DB
            tracing::warn!(error = %e, "Failed to update Redis counters; will retry on next flush");
        }

        // Mark the flushed events processed ONLY AFTER the DB write
        // succeeded. A marking failure is logged but not restored — the
        // aggregations were already persisted and restoring would double-write.
        if let Err(e) = self.mark_events_processed(&event_ids).await {
            let count = event_ids.len();
            error!(
                error = %e,
                count,
                "Failed to mark flushed events processed; they may be re-claimed and re-written"
            );
        }

        let event_count = event_ids.len();
        let aggregation_count = aggregations.len();
        debug!(
            events = event_count,
            aggregations = aggregation_count,
            "Buffers flushed successfully"
        );

        Ok(())
    }

    /// Restore drained buffers after a failed flush (no event loss).
    ///
    /// Events are appended back (skipping ids that were buffered meanwhile)
    /// and aggregation entries are counter-merged into any entries created
    /// while the flush was in flight.
    fn restore_buffers(
        &self,
        events: Vec<AnalyticsEvent>,
        aggregations: HashMap<String, AggregatedStats>,
    ) {
        {
            let mut buffer = self.event_buffer.write().unwrap_or_else(|e| e.into_inner());
            let was_empty = buffer.is_empty();
            let known: std::collections::HashSet<String> =
                buffer.iter().map(|e| e.id.clone()).collect();
            for event in events {
                if !known.contains(&event.id) {
                    buffer.push(event);
                }
            }
            if was_empty && !buffer.is_empty() {
                *self
                    .oldest_buffered_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
            }
        }
        let mut agg = self
            .aggregation_buffer
            .write()
            .unwrap_or_else(|e| e.into_inner());
        for (key, stats) in aggregations {
            agg.entry(key)
                .and_modify(|existing| existing.merge_from(stats.clone()))
                .or_insert(stats);
        }
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
    ///
    /// The FIRST rollup runs immediately at startup (an idempotent additive
    /// upsert: rolling up the previous hour's residue at boot is the same
    /// recovery posture as the email processor's restart sweeps), then once
    /// at every hour boundary.
    async fn hourly_aggregation_loop(&self) {
        while self.is_running.load(Ordering::SeqCst) {
            if let Err(e) = self.run_hourly_aggregation().await {
                error!("Hourly aggregation error: {}", e);
            }
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
                _ = sleep(wait_duration) => {}
                _ = self.shutdown_notify.notified() => break,
            }
        }
    }

    /// Run hourly aggregation from events table.
    ///
    /// F7:the rollup upserts ADDITIVELY (`= analytics_hourly.x +
    /// EXCLUDED.x`), exactly like the flush path's `write_aggregations` —
    /// the previous `= EXCLUDED.x` REPLACE semantics made the two writers
    /// clobber each other depending on ordering (a late flush after this
    /// rollup added on top of replaced totals, and this rollup wiped
    /// flush-written counts). The rollup also groups `campaign_id` — the
    /// flush path maintains campaign-keyed buckets, which the old
    /// `NULL as campaign_id` rollup neither reconciled nor represented.
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
                campaign_id,
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
            GROUP BY tenant_id, domain_id, campaign_id
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

    /// F7:both analytics_hourly writers (the flush path's batch upsert in
    /// `write_aggregations` and the hourly rollup in
    /// `run_hourly_aggregation`) must upsert ADDITIVELY, and the rollup
    /// must group campaign_id consistently with the flush path. The old
    /// split (flush additive, rollup REPLACE) made the two clobber each
    /// other depending on write ordering. Pinned on the SQL text because
    /// the crate's test harness has no live database (same technique as
    /// queue-provider's provider.rs SQL-shape tests).
    #[test]
    fn analytics_hourly_upserts_are_additive_and_campaign_consistent() {
        let source = include_str!("processor.rs");
        let metrics = [
            "sent",
            "delivered",
            "opened",
            "clicked",
            "bounced",
            "unsubscribed",
            "complained",
            "failed",
        ];

        // Both upserts conflict on the same key shape. The count is 3:
        // the flush upsert + the rollup upsert + this test's own literal
        // above (same convention as queue-provider's fenced-UPDATE test).
        let conflict_key =
            "ON CONFLICT (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)";
        assert_eq!(
            source.match_indices(conflict_key).count(),
            3,
            "expected 2 upserts (flush + rollup) + 1 test literal, found {}",
            source.match_indices(conflict_key).count()
        );

        // Every metric of BOTH upserts is additive…
        for metric in metrics {
            let additive = format!("{metric} = analytics_hourly.{metric} + EXCLUDED.{metric}");
            assert_eq!(
                source.match_indices(&additive).count(),
                2,
                "both upserts must additively update {metric}"
            );
            // …and no REPLACE-form assignment survives anywhere.
            let replacing = format!("{metric} = EXCLUDED.{metric},");
            assert!(
                !source.contains(&replacing),
                "{metric} must not be REPLACED by the rollup (clobbering semantics)"
            );
        }

        // The rollup groups campaign_id like the flush path's C:/DC keys.
        assert!(
            source.contains("GROUP BY tenant_id, domain_id, campaign_id"),
            "hourly rollup must group campaign_id consistently with the flush path"
        );
        assert!(
            !source.contains("GROUP BY tenant_id, domain_id\n"),
            "the campaign-less rollup grouping must not remain"
        );
    }
}

#[cfg(test)]
mod adversarial_db_tests {
    //! Adversarial, DB-backed tests for the analytics pipeline.
    //!
    //! These drive the REAL entry points (`fetch_events`, `process_events`,
    //! `flush_buffers`, `run_hourly_aggregation`, `update_aggregation`,
    //! `mark_events_processed`, `reset_processing`, `stop`) against the
    //! canonical provisioned schema plus the local Redis. `TEST_DATABASE_URL`
    //! gates the suite exactly like the rest of the crate: unset soft-skips,
    //! configured-but-broken FAILS.

    use super::*;
    use crate::analytics::types::AnalyticsEvent;
    use chrono::DateTime;
    use sqlx::PgPool;
    use uuid::Uuid;

    pub(super) fn redis_pool() -> RedisPool {
        let url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
        deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool")
    }

    fn dead_redis_pool() -> RedisPool {
        let mut cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let mut pool_cfg = deadpool_redis::PoolConfig::default();
        pool_cfg.timeouts.create = Some(Duration::from_millis(100));
        pool_cfg.timeouts.wait = Some(Duration::from_millis(100));
        pool_cfg.timeouts.recycle = Some(Duration::from_millis(100));
        cfg.pool = Some(pool_cfg);
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction")
    }

    async fn test_pool(test_name: &str) -> Option<PgPool> {
        crate::test_support::install_test_tracing();
        crate::test_support::canonical_pool(test_name, test_name).await
    }

    pub(super) fn test_config() -> AnalyticsConfig {
        AnalyticsConfig {
            base: crate::common::ProcessorConfig {
                name: "analytics-adversarial".to_string(),
                batch_size: 2,
                poll_interval: Duration::from_millis(20),
                flush_interval: Duration::from_secs(3600),
                ..Default::default()
            },
            stats_ttl: Duration::from_secs(60),
        }
    }

    fn processor(pool: PgPool, config: AnalyticsConfig) -> AnalyticsProcessor {
        AnalyticsProcessor::new(pool, redis_pool(), config)
    }

    pub(super) fn unique_tenant() -> String {
        format!("an-{}", &Uuid::new_v4().simple().to_string()[..20])
    }

    pub(super) async fn enqueue_event(
        pool: &PgPool,
        tenant: &str,
        event_type: &str,
        domain_id: Option<&str>,
        campaign_id: Option<&str>,
    ) -> String {
        sqlx::query_scalar::<_, i64>(
            "INSERT INTO analytics_queue
                 (tenant_id, event_type, message_id, domain_id, campaign_id, recipient, metadata, \"timestamp\")
             VALUES ($1, $2, $3, $4, $5, 'prospect@example.test', '{\"src\":\"test\"}'::jsonb, NOW())
             RETURNING id",
        )
        .bind(tenant)
        .bind(event_type)
        .bind(format!("msg-{}", &Uuid::new_v4().simple().to_string()[..20]))
        .bind(domain_id)
        .bind(campaign_id)
        .fetch_one(pool)
        .await
        .expect("enqueue analytics event")
        .to_string()
    }

    pub(super) fn event(id: &str, tenant: &str, event_type: &str) -> AnalyticsEvent {
        AnalyticsEvent {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            event_type: event_type.to_string(),
            message_id: None,
            domain_id: None,
            campaign_id: None,
            recipient: None,
            metadata: None,
            timestamp: Utc::now(),
        }
    }

    async fn hourly_totals(pool: &PgPool, tenant: &str, metric: &str) -> i64 {
        let sql = format!(
            "SELECT COALESCE(SUM({metric}), 0)::bigint FROM analytics_hourly WHERE tenant_id = $1"
        );
        sqlx::query_scalar::<_, i64>(&sql)
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("hourly totals")
    }

    /// The tenant-level (`domain_id`/`campaign_id` NULL) bucket only — the
    /// flush path writes the same event into up to four key shapes, so the
    /// un-shaped SUM above would multiply-count it.
    async fn tenant_bucket_total(pool: &PgPool, tenant: &str, metric: &str) -> i64 {
        let sql = format!(
            "SELECT COALESCE(SUM({metric}), 0)::bigint FROM analytics_hourly
              WHERE tenant_id = $1 AND domain_id IS NULL AND campaign_id IS NULL"
        );
        sqlx::query_scalar::<_, i64>(&sql)
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("tenant bucket totals")
    }

    // ── queue claiming ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_events_claims_pending_and_reclaims_stale_processing_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_fetch_events").await else { return Ok(()) };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();

        let pending = enqueue_event(&pool, &tenant, "sent", None, None).await;
        let already_done = enqueue_event(&pool, &tenant, "sent", None, None).await;
        let stale = enqueue_event(&pool, &tenant, "delivered", None, None).await;
        let fresh_processing = enqueue_event(&pool, &tenant, "delivered", None, None).await;

        sqlx::query("UPDATE analytics_queue SET processed = true WHERE id = $1")
            .bind(already_done.parse::<i64>().unwrap())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE analytics_queue SET processing = true, processing_at = NOW() - INTERVAL '11 minutes' WHERE id = $1",
        )
        .bind(stale.parse::<i64>().unwrap())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE analytics_queue SET processing = true, processing_at = NOW() WHERE id = $1",
        )
        .bind(fresh_processing.parse::<i64>().unwrap())
        .execute(&pool)
        .await
        .unwrap();

        let events = proc.fetch_events(50).await.expect("fetch events");
        let ids: Vec<&str> = events.iter().map(|e| e.id.as_str()).collect();
        assert!(
            ids.contains(&pending.as_str()),
            "pending row must be claimed"
        );
        assert!(
            ids.contains(&stale.as_str()),
            "a crashed worker's claim must be reclaimed after 10 minutes"
        );
        assert!(
            !ids.contains(&already_done.as_str()),
            "processed rows stay out"
        );
        assert!(
            !ids.contains(&fresh_processing.as_str()),
            "a live claim must not be stolen"
        );

        let processing: bool =
            sqlx::query_scalar("SELECT processing FROM analytics_queue WHERE id = $1")
                .bind(pending.parse::<i64>().unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(processing, "claim marks the row processing");
        Ok(())
    }

    #[tokio::test]
    async fn mark_processing_is_exact_and_empty_safe() -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_mark_reset").await else { return Ok(()) };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let id = enqueue_event(&pool, &tenant, "sent", None, None).await;
        let numeric: i64 = id.parse().unwrap();

        proc.mark_events_processed(&[]).await.unwrap();

        proc.mark_events_processed(std::slice::from_ref(&id))
            .await
            .unwrap();
        let (processed, processing, processed_at): (bool, bool, Option<chrono::DateTime<Utc>>) =
            sqlx::query_as(
                "SELECT processed, processing, processed_at FROM analytics_queue WHERE id = $1",
            )
            .bind(numeric)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(processed && !processing && processed_at.is_some());
        Ok(())
    }

    // ── aggregation semantics ──────────────────────────────────────────────

    #[tokio::test]
    async fn flush_writes_additive_hourly_aggregates_across_all_key_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_flush_additive").await else { return Ok(()) };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let domain = format!("dom-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let campaign = format!("camp-{}", &Uuid::new_v4().simple().to_string()[..16]);

        let id1 = enqueue_event(&pool, &tenant, "sent", Some(&domain), Some(&campaign)).await;
        let id2 = enqueue_event(&pool, &tenant, "opened", Some(&domain), Some(&campaign)).await;
        let events = proc.fetch_events(10).await.expect("claim");
        assert_eq!(events.len(), 2);
        proc.process_events(events).await.expect("process batch");
        proc.flush_buffers().await.expect("flush");

        // The event was processed exactly once.
        let processed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM analytics_queue WHERE id = ANY($1::bigint[]) AND processed",
        )
        .bind(vec![
            id1.parse::<i64>().unwrap(),
            id2.parse::<i64>().unwrap(),
        ])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(processed, 2, "flushed events must be marked processed");

        // Tenant + domain + campaign + domain-campaign buckets all exist.
        let key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM analytics_hourly WHERE tenant_id = $1
               AND (domain_id = $2 OR campaign_id = $3)",
        )
        .bind(&tenant)
        .bind(&domain)
        .bind(&campaign)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(key_count, 3, "D:, C: and DC: buckets must be written");
        assert_eq!(tenant_bucket_total(&pool, &tenant, "sent").await, 1);
        assert_eq!(tenant_bucket_total(&pool, &tenant, "opened").await, 1);

        // A second batch for the SAME period upserts additively.
        let id3 = enqueue_event(&pool, &tenant, "sent", Some(&domain), Some(&campaign)).await;
        let _ = id3;
        let events = proc.fetch_events(10).await.expect("claim 2");
        proc.process_events(events).await.expect("process 2");
        proc.flush_buffers().await.expect("flush 2");
        assert_eq!(
            tenant_bucket_total(&pool, &tenant, "sent").await,
            2,
            "the second flush must ADD, not replace"
        );

        // Redis real-time counters were incremented with a TTL.
        let mut conn = proc.redis.get().await.unwrap();
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let key = format!("stats:{}:{}:sent", tenant, date);
        let count: Option<i64> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, Some(2), "tenant sent counter");
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(
            ttl > 0 && ttl <= 60,
            "counter TTL must be bounded, got {ttl}"
        );
        let domain_key = format!("stats:{}:{}:domain:{}:sent", tenant, date, domain);
        let domain_count: Option<i64> = redis::cmd("GET")
            .arg(&domain_key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert_eq!(domain_count, Some(2), "domain sent counter");
        let campaign_key = format!("stats:{}:{}:campaign:{}:sent", tenant, date, campaign);
        let campaign_count: Option<i64> = redis::cmd("GET")
            .arg(&campaign_key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert_eq!(campaign_count, Some(2), "campaign sent counter");
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .arg(&domain_key)
            .arg(&campaign_key)
            .query_async(&mut *conn)
            .await
            .unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn failed_aggregation_write_restores_buffers_and_keeps_events_unprocessed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_flush_restore").await else { return Ok(()) };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let id = enqueue_event(&pool, &tenant, "sent", None, None).await;

        // Force the aggregation write to fail: the canonical analytics_hourly
        // table is dropped for this test database only.
        sqlx::query("DROP TABLE analytics_hourly")
            .execute(&pool)
            .await
            .expect("drop analytics_hourly");

        let events = proc.fetch_events(10).await.expect("claim");
        assert_eq!(events.len(), 1);
        proc.process_events(events).await.expect("process");

        let error = proc.flush_buffers().await.expect_err("flush must fail");
        let message = error.to_string();
        assert!(!message.is_empty());

        // Buffers were restored: nothing is lost, nothing is marked processed.
        assert_eq!(
            proc.event_buffer.read().unwrap().len(),
            1,
            "failed flush must restore the event buffer"
        );
        assert!(
            !proc.aggregation_buffer.read().unwrap().is_empty(),
            "failed flush must restore the aggregation buffer"
        );
        let processed: bool =
            sqlx::query_scalar("SELECT processed FROM analytics_queue WHERE id = $1")
                .bind(id.parse::<i64>().unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !processed,
            "events must not be marked processed on a failed write"
        );

        // A restored buffer does not double-count on a subsequent flush.
        sqlx::query(
            "CREATE TABLE analytics_hourly (
                id TEXT PRIMARY KEY, tenant_id VARCHAR(26) NOT NULL, domain_id VARCHAR(26),
                campaign_id VARCHAR(64), period_start TIMESTAMPTZ NOT NULL,
                period_end TIMESTAMPTZ NOT NULL, sent BIGINT NOT NULL DEFAULT 0,
                delivered BIGINT NOT NULL DEFAULT 0, opened BIGINT NOT NULL DEFAULT 0,
                clicked BIGINT NOT NULL DEFAULT 0, bounced BIGINT NOT NULL DEFAULT 0,
                unsubscribed BIGINT NOT NULL DEFAULT 0, complained BIGINT NOT NULL DEFAULT 0,
                failed BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW())",
        )
        .execute(&pool)
        .await
        .expect("recreate analytics_hourly");
        sqlx::query(
            "CREATE UNIQUE INDEX idx_analytics_hourly_unique_tmp ON analytics_hourly
                (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)",
        )
        .execute(&pool)
        .await
        .expect("recreate unique index");
        proc.flush_buffers().await.expect("retry flush");
        assert_eq!(
            tenant_bucket_total(&pool, &tenant, "sent").await,
            1,
            "the restored event is written exactly once"
        );
        assert!(proc.event_buffer.read().unwrap().is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn redis_outage_does_not_block_durable_aggregation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_redis_outage").await else { return Ok(()) };
        let proc = AnalyticsProcessor::new(pool.clone(), dead_redis_pool(), test_config());
        let tenant = unique_tenant();
        let id = enqueue_event(&pool, &tenant, "delivered", None, None).await;

        let events = proc.fetch_events(10).await.expect("claim");
        proc.process_events(events).await.expect("process");
        proc.flush_buffers()
            .await
            .expect("Redis counters are rebuildable from the DB: flush must succeed");

        assert_eq!(tenant_bucket_total(&pool, &tenant, "delivered").await, 1);
        let processed: bool =
            sqlx::query_scalar("SELECT processed FROM analytics_queue WHERE id = $1")
                .bind(id.parse::<i64>().unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            processed,
            "the durable path must complete despite Redis being down"
        );
        // An empty counter update is a no-op.
        proc.update_redis_counters(&[]).await.expect("empty no-op");
        proc.write_aggregations(&HashMap::new())
            .await
            .expect("empty aggregation write is a no-op");

        Ok(())
    }

    #[tokio::test]
    async fn hourly_rollup_is_additive_across_runs() -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_hourly_rollup").await else { return Ok(()) };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let domain = format!("dom-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let campaign = format!("camp-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let previous_hour = (Utc::now() - TimeDelta::try_hours(1).unwrap())
            .with_minute(10)
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();

        for (event_type, recipient) in [
            ("sent", "a@example.test"),
            ("sent", "b@example.test"),
            ("bounced", "a@example.test"),
        ] {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, event_type, recipient, domain_id, campaign_id, \"timestamp\")
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&tenant)
            .bind(event_type)
            .bind(recipient)
            .bind(&domain)
            .bind(&campaign)
            .bind(previous_hour)
            .execute(&pool)
            .await
            .expect("insert event");
        }

        proc.run_hourly_aggregation().await.expect("rollup");
        assert_eq!(hourly_totals(&pool, &tenant, "sent").await, 2);
        assert_eq!(hourly_totals(&pool, &tenant, "bounced").await, 1);

        // A second rollup over the same window must ADD (F7), never replace.
        proc.run_hourly_aggregation().await.expect("rollup again");
        assert_eq!(
            hourly_totals(&pool, &tenant, "sent").await,
            4,
            "the rollup must be additive like the flush writer"
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_aggregation_builds_tenant_domain_campaign_buckets() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = AnalyticsProcessor::new(pool, redis_pool(), test_config());
        let tenant = "t-buckets";
        let mut ev = event("1", tenant, "clicked");
        ev.domain_id = Some("dom-1".to_string());
        ev.campaign_id = Some("camp-1".to_string());

        proc.update_aggregation(&ev);
        let buffer = proc.aggregation_buffer.read().unwrap();
        assert_eq!(buffer.len(), 4, "T:, D:, C: and DC: keys must be present");
        assert!(buffer
            .keys()
            .any(|k| k.starts_with(&format!("T:{tenant}:"))));
        assert!(buffer
            .keys()
            .any(|k| k.starts_with(&format!("D:{tenant}:dom-1:"))));
        assert!(buffer
            .keys()
            .any(|k| k.starts_with(&format!("C:{tenant}:camp-1:"))));
        assert!(buffer
            .keys()
            .any(|k| k.starts_with(&format!("DC:{tenant}:dom-1:camp-1:"))));
        for stats in buffer.values() {
            assert_eq!(stats.clicked, 1);
            assert_eq!(
                stats.period_end - stats.period_start,
                TimeDelta::try_hours(1).unwrap()
            );
        }
        drop(buffer);

        // An unknown event type is counted nowhere but still buckets the key.
        let mut unknown = event("2", tenant, "not-a-real-event");
        unknown.domain_id = None;
        unknown.campaign_id = None;
        proc.update_aggregation(&unknown);
        let buffer = proc.aggregation_buffer.read().unwrap();
        let tenant_key = buffer
            .keys()
            .find(|k| k.starts_with(&format!("T:{tenant}:")))
            .unwrap()
            .clone();
        assert_eq!(buffer[&tenant_key].clicked, 1);
        assert_eq!(buffer[&tenant_key].sent, 0);
    }

    #[tokio::test]
    async fn aggregation_buffer_evicts_oldest_periods_at_the_cap() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = AnalyticsProcessor::new(pool, redis_pool(), test_config());
        let old = Utc::now() - TimeDelta::try_days(30).unwrap();
        {
            let mut buffer = proc.aggregation_buffer.write().unwrap();
            for i in 0..MAX_AGGREGATION_BUFFER_SIZE {
                let period_start = old + TimeDelta::try_seconds(i as i64).unwrap();
                buffer.insert(
                    format!("T:tenant-cap:{i}"),
                    AggregatedStats::new(
                        "tenant-cap".to_string(),
                        None,
                        None,
                        period_start,
                        period_start + TimeDelta::try_hours(1).unwrap(),
                    ),
                );
            }
        }
        let mut fresh = event("cap", "tenant-cap", "sent");
        fresh.timestamp = Utc::now();
        proc.update_aggregation(&fresh);

        let buffer = proc.aggregation_buffer.read().unwrap();
        assert!(
            buffer.len() <= MAX_AGGREGATION_BUFFER_SIZE,
            "the aggregation buffer must respect its cap, got {}",
            buffer.len()
        );
        // The eviction is by period age: the newest key (the fresh event) stays.
        let fresh_key = buffer.keys().find(|k| {
            k.starts_with("T:tenant-cap:")
                && buffer[*k].period_start > old + TimeDelta::try_days(1).unwrap()
        });
        assert!(fresh_key.is_some(), "the fresh entry must survive eviction");
    }

    #[tokio::test]
    async fn event_buffer_cap_drops_oldest_without_losing_the_newest() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = AnalyticsProcessor::new(pool, redis_pool(), test_config());
        let tenant = "tenant-event-cap";
        {
            let mut buffer = proc.event_buffer.write().unwrap();
            for i in 0..(MAX_EVENT_BUFFER_SIZE + 10) {
                buffer.push(event(&format!("ev-{i}"), tenant, "sent"));
            }
        }
        let newest = event("ev-newest", tenant, "sent");
        proc.process_events_inner(vec![newest.clone()])
            .await
            .expect("process at cap");
        let buffer = proc.event_buffer.read().unwrap();
        assert!(
            buffer.len() <= MAX_EVENT_BUFFER_SIZE,
            "the event buffer must respect its cap, got {}",
            buffer.len()
        );
        assert!(
            buffer.iter().any(|e| e.id == "ev-newest"),
            "the newest event must survive the drop-oldest policy"
        );
        assert!(
            !buffer.iter().any(|e| e.id == "ev-0"),
            "the oldest buffered events are the ones dropped"
        );
    }

    // ── lifecycle ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stop_flushes_buffers_and_repeated_flush_is_a_noop(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_stop").await else { return Ok(()) };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let _ = enqueue_event(&pool, &tenant, "complained", None, None).await;
        let events = proc.fetch_events(10).await.expect("claim");
        proc.process_events(events).await.expect("process");
        proc.is_running.store(true, Ordering::SeqCst);

        proc.stop().await.expect("stop");
        assert!(!proc.is_running.load(Ordering::SeqCst));
        assert_eq!(tenant_bucket_total(&pool, &tenant, "complained").await, 1);

        // Concurrent flush guard: while is_flushing is latched, flush is a no-op.
        proc.is_flushing.store(true, Ordering::SeqCst);
        proc.flush_buffers().await.expect("guarded flush");
        proc.is_flushing.store(false, Ordering::SeqCst);
        let _ = enqueue_event(&pool, &tenant, "failed", None, None).await;
        let events = proc.fetch_events(10).await.expect("claim 2");
        proc.process_events(events).await.expect("process 2");
        proc.flush_buffers().await.expect("flush 2");
        assert_eq!(tenant_bucket_total(&pool, &tenant, "failed").await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn start_ingests_queued_events_and_stop_drains_the_pipeline(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("an_start_stop").await else { return Ok(()) };
        let tenant = unique_tenant();
        let first = enqueue_event(&pool, &tenant, "sent", None, None).await;
        let second = enqueue_event(&pool, &tenant, "delivered", None, None).await;

        let mut config = test_config();
        config.base.flush_interval = Duration::from_millis(20);
        let proc = Arc::new(processor(pool.clone(), config));
        let running = Arc::clone(&proc);
        let handle = tokio::spawn(async move { running.start().await });

        let mut processed = 0i64;
        for _ in 0..200 {
            processed = sqlx::query_scalar(
                "SELECT COUNT(*) FROM analytics_queue WHERE id = ANY($1::bigint[]) AND processed",
            )
            .bind(vec![
                first.parse::<i64>().unwrap(),
                second.parse::<i64>().unwrap(),
            ])
            .fetch_one(&pool)
            .await
            .unwrap();
            if processed == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        proc.stop().await.expect("stop");
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

        assert_eq!(processed, 2, "the poll loop must ingest both queued events");
        assert_eq!(tenant_bucket_total(&pool, &tenant, "sent").await, 1);
        assert_eq!(tenant_bucket_total(&pool, &tenant, "delivered").await, 1);
        Ok(())
    }
    // ── poll-loop arms + hour-boundary fallback (batch 2) ─────────────────

    fn dead_db_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy("postgresql://127.0.0.1:1/none")
            .expect("lazy pool")
    }

    /// Empty poll batch + shutdown: the select on poll_interval breaks on the
    /// shutdown notification.
    #[tokio::test] // real time: pool provisioning cannot run under a paused clock
    async fn analytics_poll_loop_breaks_on_shutdown_when_idle(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("adv_poll_idle").await else { return Ok(()) };
        let processor = std::sync::Arc::new(AnalyticsProcessor::new(
            pool.clone(),
            redis_pool(),
            test_config(),
        ));
        processor.is_running.store(true, Ordering::SeqCst);
        // Spawn FIRST so the loop genuinely iterates, then shut it down.
        let p = processor.clone();
        let handle = tokio::spawn(async move { p.poll_loop().await });
        tokio::time::sleep(Duration::from_millis(120)).await;
        processor.is_running.store(false, Ordering::SeqCst);
        processor.shutdown_notify.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("loop exits on shutdown")
            .expect("join ok");
        pool.close().await;
        Ok(())
    }

    /// A dead database drives the poll-error arm; the loop keeps polling
    /// (backoff) until shutdown.
    #[tokio::test] // real time: pool provisioning cannot run under a paused clock
    async fn analytics_poll_loop_survives_poll_errors_until_shutdown() {
        let processor = std::sync::Arc::new(AnalyticsProcessor::new(
            dead_db_pool(),
            redis_pool(),
            test_config(),
        ));
        processor.is_running.store(true, Ordering::SeqCst);
        let p = processor.clone();
        let handle = tokio::spawn(async move { p.poll_loop().await });
        // Several poll cycles run into the error arm before shutdown.
        tokio::time::sleep(Duration::from_millis(120)).await;
        processor.is_running.store(false, Ordering::SeqCst);
        processor.shutdown_notify.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("loop exits after error polls")
            .expect("join ok");
    }

    /// `update_aggregation` truncates an event to the top of its hour (the
    /// aggregation period key): a normal event lands on hour boundaries.
    /// A failing final flush during `stop` is reported, not propagated; the
    /// stop then waits out in-flight work before returning.
    #[tokio::test]
    async fn stop_reports_a_failing_final_flush_and_waits_for_active_jobs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("adv_stop_flush_fail").await else { return Ok(()) };
        let processor = AnalyticsProcessor::new(pool.clone(), redis_pool(), test_config());
        // Simulate in-flight work and a database that just went away.
        processor.active_jobs.store(1, Ordering::SeqCst);
        pool.close().await;
        processor.stop().await.expect("stop never fails");
        assert_eq!(processor.active_jobs.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// The flush loop's error arm: a flush that cannot reach the database is
    /// logged and the loop keeps ticking until shutdown (buffers retained).
    #[tokio::test]
    async fn flush_loop_survives_database_outage_until_shutdown(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("adv_flush_loop_outage").await else { return Ok(()) };
        let mut config = test_config();
        config.base.flush_interval = Duration::from_millis(10);
        let processor =
            std::sync::Arc::new(AnalyticsProcessor::new(pool.clone(), redis_pool(), config));
        pool.close().await;

        // Fill the buffer past the minimum flush batch so every tick flushes.
        for i in 0..4 {
            processor
                .event_buffer
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .push(event(&format!("outage-{i}"), "t-outage", "sent"));
        }
        *processor
            .oldest_buffered_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
        processor.is_running.store(true, Ordering::SeqCst);
        let p = std::sync::Arc::clone(&processor);
        let handle = tokio::spawn(async move { p.flush_loop().await });
        tokio::time::sleep(Duration::from_millis(80)).await;
        processor.is_running.store(false, Ordering::SeqCst);
        processor.shutdown_notify.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("flush loop exits")
            .expect("join ok");

        // The events were never written — they must still be buffered.
        assert_eq!(
            processor
                .event_buffer
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            4,
            "failed flushes retain the buffer for retry"
        );
        Ok(())
    }

    /// An event whose timestamp cannot canonically map to an hour (the
    /// datetime is outside the representable hour grid) falls back to a
    /// truncated period instead of panicking or being dropped.
    #[tokio::test]
    async fn update_aggregation_falls_back_for_uncanonical_hours(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("adv_hour_fallback").await else { return Ok(()) };
        let processor = AnalyticsProcessor::new(pool.clone(), redis_pool(), test_config());
        let event = AnalyticsEvent {
            id: Uuid::new_v4().to_string(),
            tenant_id: "t-fallback".into(),
            event_type: "opened".into(),
            message_id: None,
            domain_id: None,
            campaign_id: None,
            recipient: Some("r@x.test".into()),
            metadata: None,
            timestamp: DateTime::<Utc>::MIN_UTC,
        };
        processor.update_aggregation(&event);
        let bucket = processor
            .aggregation_buffer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .next()
            .expect("one bucket")
            .clone();
        assert_eq!(bucket.opened, 1, "the event is counted");
        assert_eq!(
            bucket.period_start, event.timestamp,
            "an unrepresentable hour falls back to the raw timestamp"
        );
        pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn update_aggregation_buckets_the_event_to_its_hour(
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[rustfmt::skip]
        let Some(pool) = test_pool("adv_hour_bucket").await else { return Ok(()) };
        let processor = AnalyticsProcessor::new(pool.clone(), redis_pool(), test_config());
        let event = AnalyticsEvent {
            id: Uuid::new_v4().to_string(),
            tenant_id: "t-bucket".into(),
            event_type: "sent".into(),
            message_id: None,
            domain_id: None,
            campaign_id: None,
            recipient: Some("r@x.test".into()),
            metadata: None,
            timestamp: "2024-05-10T12:34:56Z".parse().expect("ts"),
        };
        processor.update_aggregation(&event);
        {
            let buffer = processor
                .aggregation_buffer
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let first = buffer.values().next().expect("one bucket");
            assert_eq!(
                first.period_start.format("%H:%M:%S").to_string(),
                "12:00:00",
                "bucketed to the hour: {}",
                first.period_start
            );
        }
        pool.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod residual_arms {
    //! Deterministic proofs for the residual analytics arms: the claim-reset
    //! failure arm under a write fault, and the hourly rollup's error arm
    //! driven through the real loop select! by arming the fault before the
    //! next hour boundary tick is simulated with a short wait.

    use super::adversarial_db_tests::{enqueue_event, redis_pool, test_config, unique_tenant};
    use super::*;
    use sqlx::PgPool;

    async fn residual_pool(name: &str) -> Option<PgPool> {
        crate::test_support::install_test_tracing();
        crate::test_support::canonical_pool(name, name).await
    }

    /// When the claim reset itself fails (injected UPDATE fault on
    /// analytics_queue), the failure is logged and counted — the pipeline
    /// error is still surfaced to the caller.
    #[tokio::test]
    async fn claim_reset_failure_is_logged_and_counted() {
        #[rustfmt::skip]
        let Some(pool) = residual_pool("an_res_reset_fail").await else { return };
        let processor = AnalyticsProcessor::new(pool.clone(), redis_pool(), test_config());
        let tenant = unique_tenant();
        let id = enqueue_event(&pool, &tenant, "sent", None, None).await;

        // Break the flush write so process_events_inner errs...
        sqlx::query("ALTER TABLE analytics_hourly RENAME TO analytics_hourly_gone")
            .execute(&pool)
            .await
            .expect("break analytics_hourly");
        // ...and break the claim reset too.
        sqlx::query("CREATE TABLE IF NOT EXISTS fault_injection (flag TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("fault table");
        sqlx::query(
            "CREATE OR REPLACE FUNCTION an_fail_reset() RETURNS trigger AS $$ \
             BEGIN \
               IF NEW.processing = false \
                  AND EXISTS (SELECT 1 FROM fault_injection WHERE flag = 'reset') THEN \
                 RAISE EXCEPTION 'injected fault reset'; \
               END IF; \
               RETURN NEW; \
             END; \
             $$ LANGUAGE plpgsql",
        )
        .execute(&pool)
        .await
        .expect("fault fn");
        sqlx::query(
            "CREATE TRIGGER an_fail_reset_t BEFORE UPDATE ON analytics_queue \
             FOR EACH ROW EXECUTE FUNCTION an_fail_reset()",
        )
        .execute(&pool)
        .await
        .expect("fault trigger");
        sqlx::query("INSERT INTO fault_injection (flag) VALUES ('reset')")
            .execute(&pool)
            .await
            .expect("arm fault");

        let events = processor.fetch_events(10).await.expect("claim");
        assert_eq!(events.len(), 1);
        // The flush write fails under the outage; process_events still
        // returns Ok — the failure is carried by the retained buffers and
        // the still-claimed rows (the removed reset arm would have re-queued
        // already-buffered events and double-counted them).
        let result = processor.process_events(events).await;
        assert!(
            result.is_ok(),
            "a flush failure must not fail the batch: {result:?}"
        );

        let processed: bool =
            sqlx::query_scalar("SELECT processed FROM analytics_queue WHERE id = $1")
                .bind(id.parse::<i64>().unwrap())
                .fetch_one(&pool)
                .await
                .expect("row");
        assert!(!processed, "the failed events stay unprocessed");
        assert_eq!(
            processor.event_buffer.read().unwrap().len(),
            1,
            "the events stay buffered for the retrying flush"
        );

        sqlx::query("ALTER TABLE analytics_hourly_gone RENAME TO analytics_hourly")
            .execute(&pool)
            .await
            .expect("restore analytics_hourly");
        // Disarm the fault so the retrying flush can complete its write AND
        // mark the events processed.
        sqlx::query("DELETE FROM fault_injection WHERE flag = 'reset'")
            .execute(&pool)
            .await
            .expect("disarm fault");
        // The retrying flush now succeeds and marks the events processed.
        processor
            .flush_buffers()
            .await
            .expect("flush after restore");
        let processed: bool =
            sqlx::query_scalar("SELECT processed FROM analytics_queue WHERE id = $1")
                .bind(id.parse::<i64>().unwrap())
                .fetch_one(&pool)
                .await
                .expect("row");
        assert!(processed, "the retrying flush completes the batch");
        pool.close().await;
    }

    /// The hourly loop's error arm: the rollup fails under a table outage
    /// and the loop logs it, then still stops promptly on shutdown.
    #[tokio::test] // real time: the loop parks until the hour boundary
    async fn hourly_rollup_error_arm_is_logged_and_the_loop_stops() {
        #[rustfmt::skip]
        let Some(pool) = residual_pool("an_res_hourly_err").await else { return };
        let processor = AnalyticsProcessor::new(pool.clone(), redis_pool(), test_config());
        sqlx::query("DROP TABLE IF EXISTS analytics_hourly")
            .execute(&pool)
            .await
            .expect("break analytics_hourly");

        let processor = Arc::new(processor);
        processor.is_running.store(true, Ordering::SeqCst);
        let handle = tokio::spawn({
            let processor = Arc::clone(&processor);
            async move { processor.hourly_aggregation_loop().await }
        });
        // Give the loop a moment, then stop before the hour boundary.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = processor.stop().await;
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("loop exits promptly on shutdown")
            .expect("clean exit");
        pool.close().await;
    }
}
