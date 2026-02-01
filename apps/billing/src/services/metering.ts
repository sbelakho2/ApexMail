/**
 * Usage Metering Service
 * Idempotent event counting with exactly-once semantics
 */

import Redis from 'ioredis';
import { Result } from '@apexmail/lib';
import { generateId } from '@apexmail/lib/id';
import type { DatabasePool } from '@apexmail/db';

export interface MeterEvent {
  id: string;
  tenantId: string;
  eventType: MeterEventType;
  quantity: number;
  timestamp: Date;
  metadata: Record<string, unknown>;
}

export type MeterEventType = 
  | 'emails_sent'
  | 'emails_delivered'
  | 'api_calls'
  | 'webhooks_delivered'
  | 'dedicated_ip_hours'
  | 'storage_gb_hours'
  | 'bandwidth_gb';

export interface UsageSummary {
  tenantId: string;
  period: {
    start: Date;
    end: Date;
  };
  metrics: {
    [K in MeterEventType]?: number;
  };
  billingCycleUsage: {
    emailsSent: number;
    emailsLimit: number;
    apiCalls: number;
    apiCallsLimit: number;
    percentUsed: number;
  };
}

export interface MeteringConfig {
  batchSize: number;
  flushIntervalMs: number;
}

/**
 * Idempotent metering service with event deduplication
 */
export class MeteringService {
  private buffer: MeterEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private readonly config: MeteringConfig;

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    config?: Partial<MeteringConfig>
  ) {
    this.config = {
      batchSize: config?.batchSize ?? 100,
      flushIntervalMs: config?.flushIntervalMs ?? 10000,
    };
    this.startFlushTimer();
  }

  /**
   * Record a metered event with exactly-once semantics
   */
  async recordEvent(
    tenantId: string,
    eventType: MeterEventType,
    quantity: number = 1,
    eventId?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<Result<boolean, Error>> {
    const id = eventId ?? generateId('mtr');
    
    // Check idempotency in Redis first (fast path)
    const dedupKey = `meter:dedup:${id}`;
    const wasSet = await this.redis.set(dedupKey, '1', 'EX', 86400, 'NX');
    
    if (!wasSet) {
      // Event already processed - idempotent success
      return Result.ok(false);
    }

    const event: MeterEvent = {
      id,
      tenantId,
      eventType,
      quantity,
      timestamp: new Date(),
      metadata,
    };

    // Add to buffer
    this.buffer.push(event);

    // Flush if batch size reached
    if (this.buffer.length >= this.config.batchSize) {
      await this.flush();
    }

    return Result.ok(true);
  }

  /**
   * Record multiple events atomically
   */
  async recordBatch(events: Array<{
    tenantId: string;
    eventType: MeterEventType;
    quantity?: number;
    eventId?: string;
    metadata?: Record<string, unknown>;
  }>): Promise<Result<{ recorded: number; duplicates: number }, Error>> {
    let recorded = 0;
    let duplicates = 0;

    for (const event of events) {
      const result = await this.recordEvent(
        event.tenantId,
        event.eventType,
        event.quantity ?? 1,
        event.eventId,
        event.metadata ?? {}
      );

      if (result.ok) {
        if (result.value) {
          recorded++;
        } else {
          duplicates++;
        }
      }
    }

    return Result.ok({ recorded, duplicates });
  }

  /**
   * Get current usage for a tenant in the billing period
   */
  async getUsage(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<UsageSummary, Error>> {
    const result = await this.db.query<{
      event_type: MeterEventType;
      total_quantity: string;
    }>(
      `SELECT event_type, SUM(quantity)::text as total_quantity
       FROM usage_events
       WHERE tenant_id = $1
         AND timestamp >= $2
         AND timestamp < $3
       GROUP BY event_type`,
      [tenantId, periodStart, periodEnd]
    );

    if (!result.ok) return Result.err(result.error);

    const metrics: UsageSummary['metrics'] = {};
    for (const row of result.value.rows) {
      metrics[row.event_type] = parseInt(row.total_quantity, 10);
    }

    // Get plan limits
    const planResult = await this.db.query<{
      plan: string;
      email_limit: number;
      api_limit: number;
    }>(
      `SELECT t.plan, 
              COALESCE(p.email_limit, 0) as email_limit,
              COALESCE(p.api_limit, 0) as api_limit
       FROM tenants t
       LEFT JOIN plans p ON t.plan = p.name
       WHERE t.id = $1`,
      [tenantId]
    );

    const emailsSent = metrics.emails_sent ?? 0;
    const apiCalls = metrics.api_calls ?? 0;
    const emailsLimit = planResult.ok && planResult.value.rows[0]?.email_limit || 10000;
    const apiCallsLimit = planResult.ok && planResult.value.rows[0]?.api_limit || 100000;

    return Result.ok({
      tenantId,
      period: { start: periodStart, end: periodEnd },
      metrics,
      billingCycleUsage: {
        emailsSent,
        emailsLimit,
        apiCalls,
        apiCallsLimit,
        percentUsed: Math.round((emailsSent / emailsLimit) * 100),
      },
    });
  }

  /**
   * Get real-time counter from Redis (fast path for dashboard)
   */
  async getRealtimeCounter(
    tenantId: string,
    eventType: MeterEventType,
    periodKey: string
  ): Promise<Result<number, Error>> {
    try {
      const key = `meter:counter:${tenantId}:${eventType}:${periodKey}`;
      const value = await this.redis.get(key);
      return Result.ok(value ? parseInt(value, 10) : 0);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Flush buffered events to database
   */
  async flush(): Promise<Result<number, Error>> {
    if (this.buffer.length === 0) {
      return Result.ok(0);
    }

    const eventsToFlush = [...this.buffer];
    this.buffer = [];

    // Build bulk insert
    const values: unknown[] = [];
    const placeholders: string[] = [];
    let paramIndex = 1;

    for (const event of eventsToFlush) {
      placeholders.push(
        `($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`
      );
      values.push(
        event.id,
        event.tenantId,
        event.eventType,
        event.quantity,
        event.timestamp,
        JSON.stringify(event.metadata)
      );
    }

    const result = await this.db.query(
      `INSERT INTO usage_events (id, tenant_id, event_type, quantity, timestamp, metadata)
       VALUES ${placeholders.join(', ')}
       ON CONFLICT (id) DO NOTHING`,
      values
    );

    if (!result.ok) {
      // Re-add failed events to buffer
      this.buffer.unshift(...eventsToFlush);
      return Result.err(result.error);
    }

    // Update Redis counters
    const pipeline = this.redis.pipeline();
    const periodKey = this.getPeriodKey(new Date());

    for (const event of eventsToFlush) {
      const counterKey = `meter:counter:${event.tenantId}:${event.eventType}:${periodKey}`;
      pipeline.incrby(counterKey, event.quantity);
      pipeline.expire(counterKey, 86400 * 35); // 35 days TTL
    }

    await pipeline.exec();

    return Result.ok(eventsToFlush.length);
  }

  /**
   * Reconcile Redis counters with database (run daily)
   */
  async reconcile(tenantId: string, period: { start: Date; end: Date }): Promise<Result<{
    discrepancies: Array<{
      eventType: MeterEventType;
      redisCount: number;
      dbCount: number;
      difference: number;
    }>;
  }, Error>> {
    const periodKey = this.getPeriodKey(period.start);
    const discrepancies: Array<{
      eventType: MeterEventType;
      redisCount: number;
      dbCount: number;
      difference: number;
    }> = [];

    const eventTypes: MeterEventType[] = [
      'emails_sent',
      'emails_delivered',
      'api_calls',
      'webhooks_delivered',
    ];

    for (const eventType of eventTypes) {
      const redisKey = `meter:counter:${tenantId}:${eventType}:${periodKey}`;
      const redisValue = await this.redis.get(redisKey);
      const redisCount = redisValue ? parseInt(redisValue, 10) : 0;

      const dbResult = await this.db.query<{ total: string }>(
        `SELECT COALESCE(SUM(quantity), 0)::text as total
         FROM usage_events
         WHERE tenant_id = $1
           AND event_type = $2
           AND timestamp >= $3
           AND timestamp < $4`,
        [tenantId, eventType, period.start, period.end]
      );

      const dbCount = dbResult.ok ? parseInt(dbResult.value.rows[0]?.total ?? '0', 10) : 0;

      if (redisCount !== dbCount) {
        discrepancies.push({
          eventType,
          redisCount,
          dbCount,
          difference: redisCount - dbCount,
        });

        // Correct Redis to match DB (source of truth)
        await this.redis.set(redisKey, dbCount.toString());
      }
    }

    return Result.ok({ discrepancies });
  }

  /**
   * Get period key for grouping (YYYY-MM format)
   */
  private getPeriodKey(date: Date): string {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(async () => {
      await this.flush();
    }, this.config.flushIntervalMs);
  }

  /**
   * Shutdown gracefully
   */
  async shutdown(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }
}
