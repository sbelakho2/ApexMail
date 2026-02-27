/**
 * Usage Metering Service
 * Idempotent event counting with exactly-once semantics
 * 
 * SECURITY FIXES:
 * - Fixed race condition in flush lock using atomic Redis SETNX
 * - Fixed event loss window by persisting before dedup key
 * - Buffer now preserved until successful DB write
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import { generateId } from '@apexmail/lib/id';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger();

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
  maxBufferSize: number;
}

/**
 * Idempotent metering service with event deduplication
 */
export class MeteringService {
  private buffer: MeterEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private readonly config: MeteringConfig;
  // SECURITY: Use Redis lock instead of local boolean for distributed safety
  private readonly flushLockKey = 'meter:flush:lock';
  private readonly flushLockTTL = 30; // 30 seconds max lock

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    config?: Partial<MeteringConfig>
  ) {
    this.config = {
      batchSize: config?.batchSize ?? 100,
      flushIntervalMs: config?.flushIntervalMs ?? 10000,
      maxBufferSize: config?.maxBufferSize ?? 5000,
    };
    this.startFlushTimer();
  }

  /**
   * Record a metered event with exactly-once semantics
   * SECURITY FIX: Persist event BEFORE setting dedup key to prevent event loss
   */
  async recordEvent(
    tenantId: string,
    eventType: MeterEventType,
    quantity: number = 1,
    eventId?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<Result<boolean, Error>> {
    const id = eventId ?? generateId('mtr');
    
    const event: MeterEvent = {
      id,
      tenantId,
      eventType,
      quantity,
      timestamp: new Date(),
      metadata,
    };

    // SECURITY FIX: Persist to Redis FIRST for crash recovery
    // This ensures events survive process crashes
    const pendingKey = `meter:pending:${id}`;
    await this.redis.setex(pendingKey, 3600, JSON.stringify(event)); // 1 hour TTL
    
    // Now check/set idempotency key AFTER persistence
    // If this fails, event is still in pending queue for recovery
    const dedupKey = `meter:dedup:${id}`;
    const wasSet = await this.redis.set(dedupKey, '1', 'EX', 86400, 'NX');
    
    if (!wasSet) {
      // Event already processed - clean up pending key and return idempotent success
      await this.redis.del(pendingKey);
      return Result.ok(false);
    }

    // Add to buffer (event is safely persisted in Redis)
    // D-049: Bound in-memory buffer size to prevent OOM when DB is unavailable.
    // BUG-003 FIX: Return error when buffer is full to enable backpressure
    if (this.buffer.length >= this.config.maxBufferSize) {
      const flushResult = await this.flush();
      if (!flushResult.ok) {
        logger.error('Flush attempt during buffer pressure failed', {
          error: flushResult.error.message,
        });
      }

      if (this.buffer.length >= this.config.maxBufferSize) {
        // Event is still durable in Redis pending key, but signal backpressure to caller
        logger.error('Metering buffer at capacity; returning backpressure error', {
          maxBufferSize: this.config.maxBufferSize,
          eventId: event.id,
        });
        return Result.err(new Error('Metering buffer full - apply backpressure'));
      }
    }

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
    const results = await Promise.all(
      events.map((event) => this.recordEvent(
        event.tenantId,
        event.eventType,
        event.quantity ?? 1,
        event.eventId,
        event.metadata ?? {}
      ))
    );

    let recorded = 0;
    let duplicates = 0;

    for (const result of results) {
      if (result.ok) {
        if (result.value) {
          recorded += 1;
        } else {
          duplicates += 1;
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
       FROM metering_events
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
    // IMP-003 FIX: Use ?? instead of || so that limit=0 (suspended tenant) is respected.
    // Previously: `planResult.ok && planResult.value.rows[0]?.email_limit || 10000`
    // When email_limit is 0, `0 || 10000` evaluated to 10000 — bypassing suspension.
    const emailsLimit = (planResult.ok ? planResult.value.rows[0]?.email_limit : undefined) ?? 10000;
    const apiCallsLimit = (planResult.ok ? planResult.value.rows[0]?.api_limit : undefined) ?? 100000;

    return Result.ok({
      tenantId,
      period: { start: periodStart, end: periodEnd },
      metrics,
      billingCycleUsage: {
        emailsSent,
        emailsLimit,
        apiCalls,
        apiCallsLimit,
        // Guard against division by zero
        percentUsed: emailsLimit > 0 ? Math.round((emailsSent / emailsLimit) * 100) : 0,
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
   * Events are backed by Redis for crash recovery
   * SECURITY FIX: Uses atomic Redis lock to prevent concurrent flushes
   * SECURITY FIX: Buffer preserved until successful DB write
   */
  async flush(): Promise<Result<number, Error>> {
    if (this.buffer.length === 0) {
      await this.backfillFromPending(this.config.batchSize);
    }

    if (this.buffer.length === 0) {
      return Result.ok(0);
    }

    // SECURITY FIX: Use atomic Redis lock instead of local boolean
    // This prevents race conditions in distributed deployments
    const lockAcquired = await this.redis.set(
      this.flushLockKey,
      process.pid.toString(),
      'EX', this.flushLockTTL,
      'NX'
    );
    
    if (!lockAcquired) {
      // Another process is flushing - skip this cycle
      return Result.ok(0);
    }

    try {
      // SECURITY FIX: Take a snapshot but DON'T clear buffer yet
      // Buffer will only be cleared after successful DB write
      const eventsToFlush = [...this.buffer];
      const flushedCount = eventsToFlush.length;

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
        `INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
         VALUES ${placeholders.join(', ')}
         ON CONFLICT (id) DO NOTHING`,
        values
      );

      if (!result.ok) {
        // Don't clear buffer - events will be retried on next flush
        return Result.err(result.error);
      }

      // SUCCESS: Now safe to remove flushed events from buffer
      // Remove only the events we successfully flushed (in case new events arrived)
      const flushedIds = new Set(eventsToFlush.map(e => e.id));
      this.buffer = this.buffer.filter(e => !flushedIds.has(e.id));

      // Clean up Redis pending keys after successful DB write
      const pipeline = this.redis.pipeline();
      for (const event of eventsToFlush) {
        pipeline.del(`meter:pending:${event.id}`);
      }

      // Update Redis counters
      const periodKey = this.getPeriodKey(new Date());

      for (const event of eventsToFlush) {
        const counterKey = `meter:counter:${event.tenantId}:${event.eventType}:${periodKey}`;
        pipeline.incrby(counterKey, event.quantity);
        pipeline.expire(counterKey, 86400 * 35); // 35 days TTL
      }

      await pipeline.exec();

      return Result.ok(flushedCount);
    } finally {
      // SECURITY FIX: Always release the Redis lock
      await this.redis.del(this.flushLockKey);
    }
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
         FROM metering_events
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

  /**
   * Backfill events from Redis pending queue into in-memory buffer
   * while respecting max buffer constraints.
   */
  private async backfillFromPending(maxEvents: number): Promise<void> {
    if (maxEvents <= 0 || this.buffer.length >= this.config.maxBufferSize) {
      return;
    }

    const existingIds = new Set(this.buffer.map((event) => event.id));
    const keysToLoad: string[] = [];
    let cursor = '0';

    do {
      const [newCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH', 'meter:pending:*',
        'COUNT', 200
      );
      cursor = newCursor;

      for (const key of keys) {
        const id = key.replace('meter:pending:', '');
        if (!existingIds.has(id)) {
          keysToLoad.push(key);
          existingIds.add(id);
        }

        if (
          keysToLoad.length >= maxEvents
          || this.buffer.length + keysToLoad.length >= this.config.maxBufferSize
        ) {
          break;
        }
      }

      if (
        keysToLoad.length >= maxEvents
        || this.buffer.length + keysToLoad.length >= this.config.maxBufferSize
      ) {
        break;
      }
    } while (cursor !== '0');

    if (keysToLoad.length === 0) {
      return;
    }

    const values = await this.redis.mget(...keysToLoad);
    const invalidKeys: string[] = [];

    for (let i = 0; i < keysToLoad.length; i += 1) {
      if (this.buffer.length >= this.config.maxBufferSize) break;

      const key = keysToLoad[i] ?? '';
      const raw = values[i];

      if (!raw) continue;

      try {
        const event = JSON.parse(raw) as MeterEvent;
        event.timestamp = new Date(event.timestamp);
        this.buffer.push(event);
      } catch {
        invalidKeys.push(key);
      }
    }

    if (invalidKeys.length > 0) {
      await this.redis.del(...invalidKeys);
    }
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => {
      this.flush().catch(err => {
        console.error('[Metering] Flush failed:', err instanceof Error ? err.message : err);
      });
    }, this.config.flushIntervalMs);
  }

  /**
   * Recover pending events from Redis after crash/restart
   * CRITICAL: Call this on startup to prevent data loss
   */
  async recoverPendingEvents(): Promise<Result<number, Error>> {
    try {
      // Scan for all pending events
      const pendingKeys: string[] = [];
      let cursor = '0';
      
      do {
        const [newCursor, keys] = await this.redis.scan(
          cursor,
          'MATCH', 'meter:pending:*',
          'COUNT', 100
        );
        cursor = newCursor;
        pendingKeys.push(...keys);
      } while (cursor !== '0');

      if (pendingKeys.length === 0) {
        return Result.ok(0);
      }

      // Recover events in bulk to avoid O(N) Redis roundtrips
      const events: MeterEvent[] = [];
      const values = await this.redis.mget(...pendingKeys);
      const invalidKeys: string[] = [];

      for (let i = 0; i < pendingKeys.length; i += 1) {
        const key = pendingKeys[i] ?? '';
        const data = values[i];
        if (data) {
          try {
            const event = JSON.parse(data) as MeterEvent;
            event.timestamp = new Date(event.timestamp); // Restore Date object
            events.push(event);
          } catch {
            invalidKeys.push(key);
          }
        }
      }

      if (invalidKeys.length > 0) {
        await this.redis.del(...invalidKeys);
      }

      if (events.length > 0) {
        // Add recovered events to buffer and flush immediately
        this.buffer.push(...events);
        console.error(`[Metering] Recovered ${events.length} pending events from Redis`);
        await this.flush();
      }

      return Result.ok(events.length);
    } catch (error) {
      console.error('[Metering] Failed to recover pending events:', error);
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
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
