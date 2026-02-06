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
    this.flushTimer = setInterval(() => {
      this.flushBuffers().catch(err => {
        this.logger.error('Flush error', { error: err });
      });
    }, this.config.flushInterval);

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
        const events = await this.fetchEvents(this.config.batchSize);
        
        if (events.length === 0) {
          // LISTEN/NOTIFY wakeup: sleep until notified or fallback timeout
          if (this.notifier) {
            await this.notifier.waitForNotification('queue_analytics_queue', 30_000);
          } else {
            await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
          }
          continue;
        }

        await this.processEvents(events);
      } catch (error) {
        this.logger.error('Poll error', { error });
        await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
      }
    }
  }

  private async fetchEvents(limit: number): Promise<AnalyticsEvent[]> {
    const result = await this.db.query<AnalyticsEvent>(`
      WITH claimed AS (
        SELECT id
        FROM analytics_queue
        WHERE processed = false
        ORDER BY timestamp ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED
      )
      UPDATE analytics_queue
      SET processed = true, processed_at = NOW()
      WHERE id IN (SELECT id FROM claimed)
      RETURNING
        id, tenant_id as "tenantId", event_type as "eventType",
        message_id as "messageId", domain_id as "domainId",
        campaign_id as "campaignId", recipient_email as "recipientEmail",
        metadata, timestamp
    `, [limit]);

    return result.rows;
  }

  private async processEvents(events: AnalyticsEvent[]): Promise<void> {
    this.activeJobs++;

    try {
      // Add to buffer
      this.eventBuffer.push(...events);

      // Update aggregation counters
      for (const event of events) {
        this.updateAggregation(event);
      }

      // Check if buffer should be flushed
      if (this.eventBuffer.length >= this.config.batchSize) {
        await this.flushBuffers();
      }

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

    // Create aggregation keys for different dimensions
    const keys = [
      // Tenant level
      `${event.tenantId}|${periodStart.toISOString()}`,
    ];

    if (event.domainId) {
      keys.push(`${event.tenantId}|${event.domainId}|${periodStart.toISOString()}`);
    }

    if (event.campaignId) {
      keys.push(`${event.tenantId}||${event.campaignId}|${periodStart.toISOString()}`);
    }

    if (event.domainId && event.campaignId) {
      keys.push(`${event.tenantId}|${event.domainId}|${event.campaignId}|${periodStart.toISOString()}`);
    }

    for (const key of keys) {
      let stats = this.aggregationBuffer.get(key);
      
      if (!stats) {
        // Parse key: tenantId|domainOrCampaign|campaignOrTime|timestamp
        const [tenantId, domainOrCampaign, campaignOrTime] = key.split('|');
        
        stats = {
          tenantId: tenantId ?? '',  // Ensure tenantId is always a string
          domainId: domainOrCampaign && !domainOrCampaign.startsWith('20') ? domainOrCampaign : undefined,
          campaignId: campaignOrTime && !campaignOrTime.startsWith('20') ? campaignOrTime : undefined,
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
  }

  /**
   * BUF-001 FIX: Buffer is cleared only AFTER successful write to prevent data loss.
   * Previously, buffer was cleared before try block, creating a window where 
   * new events could arrive and be lost if the write failed.
   */
  private async flushBuffers(): Promise<void> {
    if (this.eventBuffer.length === 0 && this.aggregationBuffer.size === 0) {
      return;
    }

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
  }

  private async writeAggregations(aggregations: Map<string, AggregatedStats>): Promise<void> {
    if (aggregations.size === 0) return;

    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      for (const [_key, stats] of aggregations) {
        void _key; // Key is used as map identifier but not needed in the insert
        await client.query(`
          INSERT INTO analytics_hourly (
            id, tenant_id, domain_id, campaign_id, period_start, period_end,
            sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
            created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
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
          generateId('anh'),
          stats.tenantId,
          stats.domainId ?? null,
          stats.campaignId ?? null,
          stats.periodStart,
          stats.periodEnd,
          stats.sent,
          stats.delivered,
          stats.opened,
          stats.clicked,
          stats.bounced,
          stats.unsubscribed,
          stats.complained,
          stats.failed,
        ]);
      }

      await client.query('COMMIT');

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
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

    await pipeline.exec();
  }

  private scheduleHourlyAggregation(): void {
    // Run at the start of each hour
    const now = new Date();
    const nextHour = new Date(now);
    nextHour.setHours(nextHour.getHours() + 1, 0, 0, 0);
    
    const msUntilNextHour = nextHour.getTime() - now.getTime();

    // MEM-003 FIX: Store timer reference for cleanup
    this.hourlyAggregationTimer = setTimeout(() => {
      this.runHourlyAggregation().catch(err => {
        this.logger.error('Hourly aggregation error', { error: err });
      });

      // Schedule next run
      if (this.isRunning) {
        this.scheduleHourlyAggregation();
      }
    }, msUntilNextHour);
  }

  private async runHourlyAggregation(): Promise<void> {
    this.logger.info('Running hourly aggregation');

    const previousHour = new Date();
    previousHour.setHours(previousHour.getHours() - 1, 0, 0, 0);

    const hourEnd = new Date(previousHour);
    hourEnd.setHours(hourEnd.getHours() + 1);

    try {
      // Aggregate events from the previous hour that weren't processed in real-time
      await this.db.query(`
        INSERT INTO analytics_hourly (
          id, tenant_id, domain_id, campaign_id, period_start, period_end,
          sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
          created_at, updated_at
        )
        SELECT 
          $1,
          tenant_id,
          domain_id,
          campaign_id,
          $2 as period_start,
          $3 as period_end,
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
        WHERE timestamp >= $2 AND timestamp < $3
        GROUP BY tenant_id, domain_id, campaign_id
        ON CONFLICT (tenant_id, COALESCE(domain_id, ''), COALESCE(campaign_id, ''), period_start)
        DO NOTHING
      `, [generateId('anh'), previousHour, hourEnd]);

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
      // Rollup hourly stats into daily stats
      await this.db.query(`
        INSERT INTO analytics_daily (
          id, tenant_id, domain_id, campaign_id, date,
          sent, delivered, opened, clicked, bounced, unsubscribed, complained, failed,
          unique_opens, unique_clicks,
          created_at, updated_at
        )
        SELECT 
          $1,
          tenant_id,
          domain_id,
          campaign_id,
          $2::date,
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
        WHERE period_start >= $2 AND period_start < $3
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
      `, [generateId('and'), dayStart, dayEnd]);

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
   */
  async getRealtimeStats(tenantId: string, date?: Date): Promise<Record<string, number>> {
    const dateStr = (date ?? new Date()).toISOString().split('T')[0];
    const keyPattern = `stats:${tenantId}:${dateStr}:*`;

    const keys = await this.redis.keys(keyPattern);
    if (keys.length === 0) return {};

    const values = await this.redis.mget(keys);

    const stats: Record<string, number> = {};
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const value = values[i];
      
      // Skip if key is undefined (shouldn't happen but TypeScript is cautious)
      if (key === undefined) continue;
      
      // Extract event type from key
      const parts = key.split(':');
      const eventType = parts[parts.length - 1];
      
      if (eventType !== undefined) {
        stats[eventType] = parseInt(value ?? '0', 10);
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
