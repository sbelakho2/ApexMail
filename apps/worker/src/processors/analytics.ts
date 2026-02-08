/**
 * Analytics Processor - Aggregates and processes analytics events
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import type { QueueNotifier } from '../queue-notifier.js';

interface AnalyticsProcessorConfig {
  db: Pool;
  redis: Redis;
  notifier?: QueueNotifier;
  config: {
    name: string;
    concurrency: number;
    pollInterval: number;
    batchSize: number;
    flushInterval: number;
  };
  logger: Logger;
}

interface AnalyticsEvent {
  id: string;
  tenantId: string;
  eventType: string;
  messageId?: string;
  domainId?: string;
  campaignId?: string;
  recipientEmail?: string;
  metadata?: Record<string, unknown>;
  timestamp: Date;
}

interface AggregatedStats {
  tenantId: string;
  domainId?: string;
  campaignId?: string;
  periodStart: Date;
  periodEnd: Date;
  sent: number;
  delivered: number;
  opened: number;
  clicked: number;
  bounced: number;
  unsubscribed: number;
  complained: number;
  failed: number;
}

export class AnalyticsProcessor {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly config: AnalyticsProcessorConfig['config'];
  private readonly logger: Logger;
  private readonly notifier: QueueNotifier | undefined;
  
  private isRunning = false;
  private activeJobs = 0;
  private eventBuffer: AnalyticsEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  // MEM-003 FIX: Store reference to hourly aggregation timer for cleanup
  private hourlyAggregationTimer: NodeJS.Timeout | null = null;
  private readonly aggregationBuffer = new Map<string, AggregatedStats>();
  /**
   * FIX-500-104: Mutex flag to prevent concurrent flushBuffer() calls.
   * Timer-triggered and buffer-full flushes can overlap without this.
   */
  private isFlushing = false;
  /**
   * FIX-500-107: Maximum event buffer size to prevent OOM when
   * Postgres is down and events keep accumulating.
   */
  private static readonly MAX_EVENT_BUFFER_SIZE = 50_000;
  /**
   * IMP-004: Maximum number of aggregation keys before forced eviction.
   * Without a cap, if Postgres writes fail repeatedly the aggregationBuffer
   * grows without bound → eventual OOM. With the cap, oldest entries are
   * evicted when the buffer exceeds this size, bounding memory usage.
   */
  private static readonly MAX_AGGREGATION_BUFFER_SIZE = 10_000;

  constructor(options: AnalyticsProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.config = options.config;
    this.logger = options.logger;
    this.notifier = options.notifier;
  }

  async start(): Promise<void> {
    this.logger.info('Starting analytics processor', {
      batchSize: this.config.batchSize,
      flushInterval: this.config.flushInterval,
    });

    this.isRunning = true;

    // Start flush timer
    // C-064 / D-112: Add .unref() so timer doesn't prevent process exit
    this.flushTimer = setInterval(() => {
      this.flushBuffers().catch(err => {
        this.logger.error('Flush error', { error: err });
      });
    }, this.config.flushInterval);
    this.flushTimer.unref();

    // Start polling for events
    this.poll();

    // Start hourly aggregation
    this.scheduleHourlyAggregation();
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping analytics processor');
    this.isRunning = false;

    // Stop flush timer
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }

    // MEM-003 FIX: Clear hourly aggregation timer
    if (this.hourlyAggregationTimer) {
      clearTimeout(this.hourlyAggregationTimer);
      this.hourlyAggregationTimer = null;
    }

    // Flush remaining buffers
    await this.flushBuffers();

    // Wait for active jobs
    const maxWait = 30000;
    const startTime = Date.now();
    
    while (this.activeJobs > 0 && Date.now() - startTime < maxWait) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.logger.info('Analytics processor stopped');
  }

  private async poll(): Promise<void> {
    while (this.isRunning) {
      try {
        // FIX-500-103: Honour concurrency config by fetching and processing
        // multiple batches in parallel up to the configured limit.
        const concurrency = Math.max(1, this.config.concurrency ?? 1);

        if (concurrency <= 1) {
          // Single-batch mode (original behaviour)
          const events = await this.fetchEvents(this.config.batchSize);

          if (events.length === 0) {
            if (this.notifier) {
              await this.notifier.waitForNotification('queue_analytics_queue', 30_000);
            } else {
              await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
            }
            continue;
          }

          await this.processEvents(events);
        } else {
          // Multi-batch concurrent mode
          const batches: AnalyticsEvent[][] = [];
          for (let i = 0; i < concurrency; i++) {
            const events = await this.fetchEvents(this.config.batchSize);
            if (events.length === 0) break;
            batches.push(events);
          }

          if (batches.length === 0) {
            if (this.notifier) {
              await this.notifier.waitForNotification('queue_analytics_queue', 30_000);
            } else {
              await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
            }
            continue;
          }

          // FIX-500-440: Check allSettled results for rejections instead of silently dropping errors.
          const settledResults = await Promise.allSettled(batches.map(b => this.processEvents(b)));
          for (const result of settledResults) {
            if (result.status === 'rejected') {
              this.logger.error('FIX-500-440: Concurrent batch processing failed', {
                error: result.reason instanceof Error ? result.reason.message : String(result.reason),
              });
            }
          }
        }
      } catch (error) {
        this.logger.error('Poll error', { error });
        await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
      }
    }
  }

  /**
   * FIX-500-002: Two-phase analytics processing.
   * Phase 1 (fetchEvents): Mark events as 'processing' — they won't be picked up
   * by other workers but aren't considered "done" yet.
   * Phase 2 (markEventsProcessed): After successful flush, mark them as 'processed'.
   * If the flush fails, events remain in 'processing' state and can be recovered
   * by a stale-processing sweep (same pattern as email_queue).
   */
  private async fetchEvents(limit: number): Promise<AnalyticsEvent[]> {
    const result = await this.db.query<AnalyticsEvent>(`
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
        id, tenant_id as "tenantId", event_type as "eventType",
        message_id as "messageId", domain_id as "domainId",
        campaign_id as "campaignId", recipient_email as "recipientEmail",
        metadata, timestamp
    `, [limit]);

    return result.rows;
  }

  private async markEventsProcessed(eventIds: string[]): Promise<void> {
    if (eventIds.length === 0) return;
    await this.db.query(
      `UPDATE analytics_queue SET processed = true, processed_at = NOW(), processing = false WHERE id = ANY($1)`,
      [eventIds]
    );
  }

  private async processEvents(events: AnalyticsEvent[]): Promise<void> {
    this.activeJobs++;

    try {
      // Add to buffer
      this.eventBuffer.push(...events);

      // FIX-500-107: Enforce event buffer size cap to prevent OOM
      if (this.eventBuffer.length > AnalyticsProcessor.MAX_EVENT_BUFFER_SIZE) {
        const dropped = this.eventBuffer.length - AnalyticsProcessor.MAX_EVENT_BUFFER_SIZE;
        this.eventBuffer = this.eventBuffer.slice(dropped);
        this.logger.warn('FIX-500-107: Event buffer exceeded cap, dropped oldest events', {
          dropped,
          cap: AnalyticsProcessor.MAX_EVENT_BUFFER_SIZE,
        });
      }

      // Update aggregation counters
      for (const event of events) {
        this.updateAggregation(event);
      }

      // Check if buffer should be flushed
      if (this.eventBuffer.length >= this.config.batchSize) {
        await this.flushBuffers();
      }

      // FIX-500-002: Mark events as fully processed after successful buffering/flushing
      await this.markEventsProcessed(events.map(e => e.id));
    } catch (error) {
      // FIX-500-002: Reset processing flag so stale-recovery sweep can reclaim them
      const eventIds = events.map(e => e.id);
      await this.db.query(
        `UPDATE analytics_queue SET processing = false, processing_at = NULL WHERE id = ANY($1)`,
        [eventIds]
      ).catch(resetErr => {
        this.logger.error('Failed to reset processing flag on analytics events', { error: resetErr });
      });
      throw error;
    } finally {
      this.activeJobs--;
    }
  }

  private updateAggregation(event: AnalyticsEvent): void {
    // Get current hour bucket
    const periodStart = new Date(event.timestamp);
    periodStart.setMinutes(0, 0, 0);
    const periodEnd = new Date(periodStart);
    periodEnd.setHours(periodEnd.getHours() + 1);

    // FIX-500-006: Use structured aggregation keys with explicit type prefix
    // to eliminate ambiguous parsing. Previous format used `||` for campaign-only
    // keys, which created 4-segment keys indistinguishable from domain+campaign keys.
    // New format: "T:<tenantId>:<periodISO>" for tenant-level,
    //             "D:<tenantId>:<domainId>:<periodISO>" for domain-level,
    //             "C:<tenantId>:<campaignId>:<periodISO>" for campaign-level,
    //             "DC:<tenantId>:<domainId>:<campaignId>:<periodISO>" for both.
    // FIX-500-439: Use epoch milliseconds for the period key instead of ISO string.
    // ISO strings contain ':' characters (e.g., 2025-01-01T00:00:00.000Z) which
    // are ambiguous with the ':' delimiter used between key segments. Epoch format
    // is guaranteed to contain only digits, eliminating parsing ambiguity.
    const periodKey = String(periodStart.getTime());
    const keys: Array<{ key: string; domainId?: string; campaignId?: string }> = [
      { key: `T:${event.tenantId}:${periodKey}` },
    ];

    if (event.domainId) {
      keys.push({ key: `D:${event.tenantId}:${event.domainId}:${periodKey}`, domainId: event.domainId });
    }

    if (event.campaignId) {
      keys.push({ key: `C:${event.tenantId}:${event.campaignId}:${periodKey}`, campaignId: event.campaignId });
    }

    if (event.domainId && event.campaignId) {
      keys.push({ key: `DC:${event.tenantId}:${event.domainId}:${event.campaignId}:${periodKey}`, domainId: event.domainId, campaignId: event.campaignId });
    }

    for (const { key, domainId, campaignId } of keys) {
      let stats = this.aggregationBuffer.get(key);
      
      if (!stats) {
        stats = {
          tenantId: event.tenantId,
          domainId,
          campaignId,
          periodStart,
          periodEnd,
          sent: 0,
          delivered: 0,
          opened: 0,
          clicked: 0,
          bounced: 0,
          unsubscribed: 0,
          complained: 0,
          failed: 0,
        };
        this.aggregationBuffer.set(key, stats);
      }

      // Stats is guaranteed to be defined here since we either got it from the buffer
      // or just created it above
      const currentStats = stats!;

      // Increment counter based on event type
      switch (event.eventType) {
        case 'sent':
          currentStats.sent++;
          break;
        case 'delivered':
          currentStats.delivered++;
          break;
        case 'opened':
          currentStats.opened++;
          break;
        case 'clicked':
          currentStats.clicked++;
          break;
        case 'bounced':
          currentStats.bounced++;
          break;
        case 'unsubscribed':
          currentStats.unsubscribed++;
          break;
        case 'complained':
          currentStats.complained++;
          break;
        case 'failed':
          currentStats.failed++;
          break;
      }
    }

    // IMP-004: Evict oldest entries when buffer exceeds cap to prevent OOM.
    // Map iteration order is insertion order, so the first keys are the oldest.
    if (this.aggregationBuffer.size > AnalyticsProcessor.MAX_AGGREGATION_BUFFER_SIZE) {
      const excess = this.aggregationBuffer.size - AnalyticsProcessor.MAX_AGGREGATION_BUFFER_SIZE;
      let removed = 0;
      for (const oldKey of this.aggregationBuffer.keys()) {
        if (removed >= excess) break;
        this.aggregationBuffer.delete(oldKey);
        removed++;
      }
      this.logger.warn('Aggregation buffer exceeded cap, evicted oldest entries', {
        evicted: removed,
        bufferSize: this.aggregationBuffer.size,
        cap: AnalyticsProcessor.MAX_AGGREGATION_BUFFER_SIZE,
      });
    }
  }

  /**
   * BUF-001 FIX: Buffer is cleared only AFTER successful write to prevent data loss.
   * Previously, buffer was cleared before try block, creating a window where 
   * new events could arrive and be lost if the write failed.
   */
  private async flushBuffers(): Promise<void> {
    // FIX-500-104: Mutex to prevent concurrent flushes
    if (this.isFlushing) return;

    if (this.eventBuffer.length === 0 && this.aggregationBuffer.size === 0) {
      return;
    }

    this.isFlushing = true;
    try {

    this.logger.debug('Flushing analytics buffers', {
      events: this.eventBuffer.length,
      aggregations: this.aggregationBuffer.size,
    });

    // Take snapshots but DON'T clear buffers yet
    const events = [...this.eventBuffer];
    const aggregations = new Map(this.aggregationBuffer);
    
    // Create sets to track which items we took for flushing
    const eventIds = new Set(events.map((event) => event.id));
    const aggregationKeys = new Set(aggregations.keys());

    try {
      // Write aggregations to database
      await this.writeAggregations(aggregations);

      // Update real-time counters in Redis
      await this.updateRedisCounters(events);

      // SUCCESS: Now safe to remove flushed items from buffers
      // Only remove the specific events we flushed (keep any new arrivals)
      this.eventBuffer = this.eventBuffer.filter((event) => !eventIds.has(event.id));
      
      // Remove only the aggregation keys we successfully flushed
      for (const key of aggregationKeys) {
        this.aggregationBuffer.delete(key);
      }

      this.logger.debug('Buffers flushed successfully', {
        events: events.length,
        aggregations: aggregations.size,
      });

    } catch (error) {
      // On error, don't clear - items remain in buffer for retry
      // Any new events that arrived during flush attempt are preserved
      this.logger.error('Failed to flush buffers - will retry', { error });
      throw error;
    }
    } finally {
      // FIX-500-104: Release flush mutex
      this.isFlushing = false;
    }
  }

  /**
   * Batch upsert: single multi-row INSERT … ON CONFLICT instead of N individual queries.
   * Uses unnest() to pass typed arrays, giving PostgreSQL one parse/plan/execute cycle
   * regardless of how many aggregation buckets are in the batch.
   */
  private async writeAggregations(aggregations: Map<string, AggregatedStats>): Promise<void> {
    if (aggregations.size === 0) return;

    // Build parallel arrays for each column
    const ids: string[] = [];
    const tenantIds: string[] = [];
    const domainIds: (string | null)[] = [];
    const campaignIds: (string | null)[] = [];
    const periodStarts: Date[] = [];
    const periodEnds: Date[] = [];
    const sentArr: number[] = [];
    const deliveredArr: number[] = [];
    const openedArr: number[] = [];
    const clickedArr: number[] = [];
    const bouncedArr: number[] = [];
    const unsubscribedArr: number[] = [];
    const complainedArr: number[] = [];
    const failedArr: number[] = [];

    for (const stats of aggregations.values()) {
      ids.push(generateId('anh'));
      tenantIds.push(stats.tenantId);
      domainIds.push(stats.domainId ?? null);
      campaignIds.push(stats.campaignId ?? null);
      periodStarts.push(stats.periodStart);
      periodEnds.push(stats.periodEnd);
      sentArr.push(stats.sent);
      deliveredArr.push(stats.delivered);
      openedArr.push(stats.opened);
      clickedArr.push(stats.clicked);
      bouncedArr.push(stats.bounced);
      unsubscribedArr.push(stats.unsubscribed);
      complainedArr.push(stats.complained);
      failedArr.push(stats.failed);
    }

    await this.db.query(`
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
        unnest($7::int[]),
        unnest($8::int[]),
        unnest($9::int[]),
        unnest($10::int[]),
        unnest($11::int[]),
        unnest($12::int[]),
        unnest($13::int[]),
        unnest($14::int[]),
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
    `, [
      ids, tenantIds, domainIds, campaignIds,
      periodStarts, periodEnds,
      sentArr, deliveredArr, openedArr, clickedArr,
      bouncedArr, unsubscribedArr, complainedArr, failedArr,
    ]);
  }

  private async updateRedisCounters(events: AnalyticsEvent[]): Promise<void> {
    const pipeline = this.redis.pipeline();

    // Group events by tenant and type
    const counters = new Map<string, number>();

    for (const event of events) {
      const todayKey = `stats:${event.tenantId}:${new Date().toISOString().split('T')[0]}`;
      
      // Increment daily counters
      const typeKey = `${todayKey}:${event.eventType}`;
      counters.set(typeKey, (counters.get(typeKey) ?? 0) + 1);

      // Increment domain counters
      if (event.domainId) {
        const domainKey = `${todayKey}:domain:${event.domainId}:${event.eventType}`;
        counters.set(domainKey, (counters.get(domainKey) ?? 0) + 1);
      }

      // Increment campaign counters
      if (event.campaignId) {
        const campaignKey = `${todayKey}:campaign:${event.campaignId}:${event.eventType}`;
        counters.set(campaignKey, (counters.get(campaignKey) ?? 0) + 1);
      }
    }

    // Execute all increments
    for (const [key, value] of counters) {
      pipeline.incrby(key, value);
      pipeline.expire(key, 7 * 24 * 60 * 60); // 7 day TTL
    }

    // FIX-500-438: Check pipeline results for individual command failures.
    // Previously the return value was ignored, silently dropping partial errors.
    const results = await pipeline.exec();
    if (results) {
      for (const [err] of results) {
        if (err) {
          this.logger.warn('FIX-500-438: Redis pipeline command failed', { error: err.message });
        }
      }
    }
  }

  private scheduleHourlyAggregation(): void {
    // Run at the start of each hour
    const now = new Date();
    const nextHour = new Date(now);
    nextHour.setHours(nextHour.getHours() + 1, 0, 0, 0);
    
    const msUntilNextHour = nextHour.getTime() - now.getTime();

    // MEM-003 FIX: Store timer reference for cleanup
    // D-113: Add .unref() so timer doesn't prevent process exit
    this.hourlyAggregationTimer = setTimeout(async () => {
      try {
        await this.runHourlyAggregation();
      } catch (err) {
        this.logger.error('Hourly aggregation error', { error: err });
      }

      // FIX-500-105: Schedule next run AFTER completion to avoid drift.
      // Previously scheduled before the run started, causing accumulated
      // drift when the aggregation takes significant time.
      if (this.isRunning) {
        this.scheduleHourlyAggregation();
      }
    }, msUntilNextHour);
    this.hourlyAggregationTimer.unref();
  }

  private async runHourlyAggregation(): Promise<void> {
    this.logger.info('Running hourly aggregation');

    const previousHour = new Date();
    previousHour.setHours(previousHour.getHours() - 1, 0, 0, 0);

    const hourEnd = new Date(previousHour);
    hourEnd.setHours(hourEnd.getHours() + 1);

    try {
      // Aggregate events from the previous hour that weren't processed in real-time
      // FIX-001: Use gen_random_uuid() instead of a single $1 ID parameter.
      // The GROUP BY produces N rows (one per tenant/domain/campaign combo),
      // so each row needs its own unique ID. Previously $1 was the same for
      // all rows, causing ON CONFLICT DO NOTHING to silently drop all but one.
      await this.db.query(`
        INSERT INTO analytics_hourly (
          id, tenant_id, domain_id, campaign_id, period_start, period_end,
          sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
          created_at, updated_at
        )
        SELECT 
          gen_random_uuid()::text,
          tenant_id,
          domain_id,
          campaign_id,
          $1 as period_start,
          $2 as period_end,
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
        DO NOTHING
      `, [previousHour, hourEnd]);

      // Run daily rollup at midnight
      if (previousHour.getHours() === 23) {
        await this.runDailyRollup(previousHour);
      }

      this.logger.info('Hourly aggregation complete', {
        periodStart: previousHour.toISOString(),
        periodEnd: hourEnd.toISOString(),
      });

    } catch (error) {
      this.logger.error('Hourly aggregation failed', { error });
      throw error;
    }
  }

  private async runDailyRollup(date: Date): Promise<void> {
    this.logger.info('Running daily rollup');

    const dayStart = new Date(date);
    dayStart.setHours(0, 0, 0, 0);

    const dayEnd = new Date(dayStart);
    dayEnd.setDate(dayEnd.getDate() + 1);

    try {
      // FIX-001: Use gen_random_uuid() instead of a single $1 ID parameter.
      // Same bug as hourly aggregation — GROUP BY produces N rows that all
      // need unique IDs.
      await this.db.query(`
        INSERT INTO analytics_daily (
          id, tenant_id, domain_id, campaign_id, date,
          sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
          unique_opens, unique_clicks,
          created_at, updated_at
        )
        SELECT 
          gen_random_uuid()::text,
          tenant_id,
          domain_id,
          campaign_id,
          $1::date,
          SUM(sent),
          SUM(delivered),
          SUM(opened),
          SUM(clicked),
          SUM(bounced),
          SUM(unsubscribed),
          SUM(complained),
          SUM(failed),
          0, -- unique_opens calculated separately
          0, -- unique_clicks calculated separately
          NOW(),
          NOW()
        FROM analytics_hourly
        WHERE period_start >= $1 AND period_start < $2
        GROUP BY tenant_id, domain_id, campaign_id
        ON CONFLICT (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), date)
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
      `, [dayStart, dayEnd]);

      // Calculate unique opens and clicks
      await this.db.query(`
        UPDATE analytics_daily ad
        SET 
          unique_opens = (
            SELECT COUNT(DISTINCT recipient_email)
            FROM events e
            WHERE e.tenant_id = ad.tenant_id
              AND (e.domain_id = ad.domain_id OR (e.domain_id IS NULL AND ad.domain_id IS NULL))
              AND (e.campaign_id = ad.campaign_id OR (e.campaign_id IS NULL AND ad.campaign_id IS NULL))
              AND e.event_type = 'opened'
              AND e.timestamp >= $1 AND e.timestamp < $2
          ),
          unique_clicks = (
            SELECT COUNT(DISTINCT recipient_email)
            FROM events e
            WHERE e.tenant_id = ad.tenant_id
              AND (e.domain_id = ad.domain_id OR (e.domain_id IS NULL AND ad.domain_id IS NULL))
              AND (e.campaign_id = ad.campaign_id OR (e.campaign_id IS NULL AND ad.campaign_id IS NULL))
              AND e.event_type = 'clicked'
              AND e.timestamp >= $1 AND e.timestamp < $2
          ),
          updated_at = NOW()
        WHERE ad.date = $1::date
      `, [dayStart, dayEnd]);

      this.logger.info('Daily rollup complete', { date: dayStart.toISOString().split('T')[0] });

    } catch (error) {
      this.logger.error('Daily rollup failed', { error });
      throw error;
    }
  }

  /**
   * Get real-time stats from Redis
   * C-061: Use SCAN instead of KEYS to avoid blocking Redis
   */
  async getRealtimeStats(tenantId: string, date?: Date): Promise<Record<string, number>> {
    const dateStr = (date ?? new Date()).toISOString().split('T')[0];

    // FIX-500-059: Construct explicit keys instead of using SCAN with wildcard pattern
    const eventTypes = ['sent', 'delivered', 'opened', 'clicked', 'bounced', 'complained', 'unsubscribed', 'failed', 'deferred', 'dropped'];
    const keys = eventTypes.map(et => `stats:${tenantId}:${dateStr}:${et}`);
    const values = await this.redis.mget(keys);

    const stats: Record<string, number> = {};
    for (let i = 0; i < eventTypes.length; i++) {
      const val = values[i];
      if (val !== null && val !== undefined) {
        stats[eventTypes[i]!] = parseInt(val, 10);
      }
    }
    return stats;
  }
}

/**
 * Helper to queue analytics events from other parts of the system
 */
export async function trackAnalyticsEvent(
  db: Pool,
  event: Omit<AnalyticsEvent, 'id'>
): Promise<void> {
  await db.query(`
    INSERT INTO analytics_queue (
      id, tenant_id, event_type, message_id, domain_id, campaign_id,
      recipient_email, metadata, timestamp, processed
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
  `, [
    generateId('anq'),
    event.tenantId,
    event.eventType,
    event.messageId ?? null,
    event.domainId ?? null,
    event.campaignId ?? null,
    event.recipientEmail ?? null,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.timestamp,
  ]);
}
