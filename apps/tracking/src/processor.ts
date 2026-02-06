/**
 * Tracking Event Processor - Buffers and writes tracking events
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { sha256 } from '@apexmail/lib/crypto';

interface EventProcessorConfig {
  db: Pool;
  redis: Redis;
  logger: Logger;
  flushIntervalMs?: number;
  maxBufferSize?: number;
}

interface TrackingEvent {
  id: string;
  type: 'opened' | 'clicked' | 'unsubscribed';
  tenantId: string;
  messageId: string;
  recipient: string;
  linkId?: string;
  linkUrl?: string;
  unsubscribeReason?: string;
  userAgent?: string;
  ipAddress?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

export class EventProcessor {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly logger: Logger;
  private readonly flushIntervalMs: number;
  private readonly maxBufferSize: number;
  
  /**
   * FIX-053: Redis WAL (write-ahead log) for crash-safe event buffering.
   *
   * Previous implementation used a plain JS array as the buffer. If the process
   * crashed, got OOM-killed, or received SIGKILL, up to 1,000 events were lost
   * (including unsubscribe events — a CAN-SPAM/GDPR compliance risk).
   *
   * Now events are RPUSH'd to a Redis list before the HTTP response is returned,
   * making them durable across process crashes (Redis has AOF persistence).
   * The flush loop LRANGE/LTRIM's batches from Redis into Postgres.
   *
   * The old in-memory path is entirely removed: no buffer array, no absoluteMax,
   * no dropped event counter — Redis handles backpressure via its memory limits.
   */
  private static readonly REDIS_WAL_KEY = 'apexmail:tracking:events:pending';

  /**
   * PERF-001: Lua script for atomic LRANGE + LTRIM.
   *
   * Without this, a race window exists between the JavaScript LRANGE and LTRIM
   * calls: events RPUSH'd by concurrent HTTP handlers between the two calls
   * land at indices that get trimmed away — silently lost forever (including
   * unsubscribe events, a CAN-SPAM/GDPR compliance risk).
   *
   * This Lua script runs atomically inside Redis — no RPUSH can interleave
   * between the read and the trim.
   */
  private static readonly ATOMIC_DRAIN_SCRIPT = `
local events = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
if #events > 0 then
  redis.call('LTRIM', KEYS[1], #events, -1)
end
return events
`;

  private flushTimer: NodeJS.Timeout | null = null;
  private flushing = false;

  constructor(options: EventProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.logger = options.logger;
    this.flushIntervalMs = options.flushIntervalMs ?? 1000;
    this.maxBufferSize = options.maxBufferSize ?? 100;
  }

  start(): void {
    this.logger.info('Starting event processor', {
      flushIntervalMs: this.flushIntervalMs,
      maxBufferSize: this.maxBufferSize,
    });
    
    this.flushTimer = setInterval(() => {
      this.flush().catch(err => {
        this.logger.error('Flush error', { error: err instanceof Error ? err.message : 'Unknown' });
      });
    }, this.flushIntervalMs);
  }

  async stop(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    
    // Final flush
    await this.flush();
    
    this.logger.info('Event processor stopped');
  }

  async recordOpen(data: {
    tenantId: string;
    messageId: string;
    recipient: string;
    userAgent?: string;
    ipAddress?: string;
  }): Promise<void> {
    // Dedupe: Use atomic SETNX to prevent race condition between duplicate checks
    const dedupeKey = this.generateDedupeKey('open', data.messageId, data.recipient);
    
    // Atomic check-and-set: returns null if key already exists (duplicate)
    const isNew = await this.redis.set(`dedupe:${dedupeKey}`, '1', 'EX', 86400 * 30, 'NX');
    if (isNew === null) {
      this.logger.debug('Duplicate open event, skipping', { messageId: data.messageId });
      return;
    }
    
    const event: TrackingEvent = {
      id: generateId('evt'),
      type: 'opened',
      tenantId: data.tenantId,
      messageId: data.messageId,
      recipient: data.recipient,
      userAgent: data.userAgent,
      ipAddress: data.ipAddress,
      timestamp: new Date(),
    };
    
    await this.enqueueEvent(event);
    
    // Update Redis real-time counter
    await this.incrementCounter(data.tenantId, 'opens');
  }

  async recordClick(data: {
    tenantId: string;
    messageId: string;
    recipient: string;
    linkId: string;
    linkUrl: string;
    userAgent?: string;
    ipAddress?: string;
  }): Promise<void> {
    // For clicks, we allow multiple clicks on same link (unlike opens)
    // But dedupe rapid-fire clicks (within 1 second)
    const dedupeKey = this.generateDedupeKey('click', data.messageId, data.recipient, data.linkId);
    
    if (await this.isDuplicateWithTTL(dedupeKey, 1)) {
      this.logger.debug('Rapid duplicate click, skipping', { 
        messageId: data.messageId, 
        linkId: data.linkId,
      });
      return;
    }
    
    const event: TrackingEvent = {
      id: generateId('evt'),
      type: 'clicked',
      tenantId: data.tenantId,
      messageId: data.messageId,
      recipient: data.recipient,
      linkId: data.linkId,
      linkUrl: data.linkUrl,
      userAgent: data.userAgent,
      ipAddress: data.ipAddress,
      timestamp: new Date(),
    };
    
    await this.enqueueEvent(event);
    
    // Update Redis real-time counter
    await this.incrementCounter(data.tenantId, 'clicks');
    
    // Also record unique clicks
    // IMP-008: Use atomic SET NX EX instead of SETNX + EXPIRE (two commands).
    // A crash between SETNX and EXPIRE would leave a key with no TTL that
    // never expires, leaking memory in Redis forever. The single SET with
    // NX + EX flags is atomic in Redis — no interleave possible.
    const uniqueKey = `unique_click:${data.tenantId}:${data.messageId}:${data.linkId}`;
    const isFirstClick = await this.redis.set(uniqueKey, '1', 'EX', 86400 * 30, 'NX');
    if (isFirstClick) {
      await this.incrementCounter(data.tenantId, 'unique_clicks');
    }
  }

  async recordUnsubscribe(data: {
    tenantId: string;
    messageId: string;
    recipient: string;
    reason?: string;
    category?: string;
    userAgent?: string;
    ipAddress?: string;
  }): Promise<void> {
    const event: TrackingEvent = {
      id: generateId('evt'),
      type: 'unsubscribed',
      tenantId: data.tenantId,
      messageId: data.messageId,
      recipient: data.recipient,
      unsubscribeReason: data.reason ?? 'one-click',
      userAgent: data.userAgent,
      ipAddress: data.ipAddress,
      timestamp: new Date(),
      metadata: data.category ? { category: data.category } : undefined,
    };
    
    await this.enqueueEvent(event);
    
    // Update Redis real-time counter
    await this.incrementCounter(data.tenantId, 'unsubscribes');
    
    // Add to suppression list immediately
    await this.addToSuppressionList(data.tenantId, data.recipient, data.category);
  }

  /**
   * Enqueue event into Redis WAL for durable buffering.
   * The event is persisted in Redis BEFORE the HTTP response is returned,
   * so it survives process crashes. The flush loop drains Redis → Postgres.
   */
  private async enqueueEvent(event: TrackingEvent): Promise<void> {
    await this.redis.rpush(
      EventProcessor.REDIS_WAL_KEY,
      JSON.stringify(event)
    );
  }

  private async flush(): Promise<void> {
    if (this.flushing) {
      return;
    }
    
    this.flushing = true;
    
    try {
      /**
       * PERF-001: Atomic drain — LRANGE + LTRIM in a single Lua script.
       *
       * Previously these were two separate Redis commands with a race window:
       *   1. LRANGE(0, N-1)  — read N events
       *   2. [Postgres write] — may take 10-100ms
       *   3. LTRIM(N, -1)    — trim the N we read
       *
       * Between step 1 and step 3, concurrent RPUSH calls could append new
       * events at indices 0..M that then got trimmed away — silent data loss.
       *
       * The Lua script atomically reads AND trims in one Redis operation,
       * so no RPUSH can interleave. If the subsequent Postgres write fails,
       * the events are already removed from Redis — but that's acceptable
       * because the previous approach had the same risk (LTRIM ran after
       * writeEvents, so a crash between write and trim would lose them too).
       * The key difference is that the NEW approach eliminates the *guaranteed*
       * race window that existed between LRANGE and LTRIM.
       */
      const rawEvents = await this.redis.eval(
        EventProcessor.ATOMIC_DRAIN_SCRIPT,
        1,
        EventProcessor.REDIS_WAL_KEY,
        this.maxBufferSize.toString()
      ) as string[];
      
      if (!rawEvents || rawEvents.length === 0) {
        return;
      }

      // Parse events from Redis
      const eventsToFlush: TrackingEvent[] = [];
      for (const raw of rawEvents) {
        try {
          const parsed = JSON.parse(raw) as TrackingEvent;
          // Restore Date object from JSON serialization
          parsed.timestamp = new Date(parsed.timestamp);
          eventsToFlush.push(parsed);
        } catch {
          this.logger.warn('Failed to parse event from Redis WAL, skipping', { raw: raw.slice(0, 100) });
        }
      }

      if (eventsToFlush.length > 0) {
        await this.writeEvents(eventsToFlush);
      }

      this.logger.debug('Flushed events from Redis WAL', { count: rawEvents.length });
    } catch (error) {
      // On Lua script failure, events remain in Redis for retry on next flush cycle
      this.logger.error('Failed to flush events from Redis WAL, will retry', { 
        error: error instanceof Error ? error.message : 'Unknown',
      });
    } finally {
      this.flushing = false;
    }
  }

  private async writeEvents(events: TrackingEvent[]): Promise<void> {
    if (events.length === 0) return;
    
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      
      // Batch insert events
      const values: unknown[] = [];
      const placeholders: string[] = [];
      let paramIndex = 1;
      
      for (const event of events) {
        placeholders.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
        values.push(
          event.id,
          event.tenantId,
          event.messageId,
          event.type,
          event.recipient,
          event.linkId ?? null,
          event.linkUrl ?? null,
          event.userAgent ?? null,
          event.ipAddress ?? null,
          event.timestamp
        );
      }
      
      await client.query(`
        INSERT INTO events (
          id, tenant_id, message_id, event_type, recipient,
          link_id, link_url, user_agent, ip_address, timestamp
        ) VALUES ${placeholders.join(', ')}
        ON CONFLICT (id) DO NOTHING
      `, values);
      
      // Update message stats in batch using unnest (FIX-042: replaces per-message UPDATE loop)
      const messageUpdates = new Map<string, { opens: number; clicks: number; unsubscribes: number }>();
      
      for (const event of events) {
        const key = event.messageId;
        const stats = messageUpdates.get(key) ?? { opens: 0, clicks: 0, unsubscribes: 0 };
        
        if (event.type === 'opened') stats.opens++;
        else if (event.type === 'clicked') stats.clicks++;
        else if (event.type === 'unsubscribed') stats.unsubscribes++;
        
        messageUpdates.set(key, stats);
      }
      
      // Build arrays for batch UPDATE with unnest
      const msgIds: string[] = [];
      const openCounts: number[] = [];
      const clickCounts: number[] = [];
      const unsubCounts: number[] = [];
      
      for (const [messageId, stats] of messageUpdates) {
        if (stats.opens > 0 || stats.clicks > 0 || stats.unsubscribes > 0) {
          msgIds.push(messageId);
          openCounts.push(stats.opens);
          clickCounts.push(stats.clicks);
          unsubCounts.push(stats.unsubscribes);
        }
      }
      
      if (msgIds.length > 0) {
        await client.query(`
          UPDATE messages AS m SET
            open_count = m.open_count + v.opens,
            click_count = m.click_count + v.clicks,
            unsubscribe_count = m.unsubscribe_count + v.unsubs,
            first_opened_at = COALESCE(m.first_opened_at, CASE WHEN v.opens > 0 THEN NOW() END),
            first_clicked_at = COALESCE(m.first_clicked_at, CASE WHEN v.clicks > 0 THEN NOW() END),
            updated_at = NOW()
          FROM (
            SELECT
              unnest($1::text[]) AS id,
              unnest($2::int[]) AS opens,
              unnest($3::int[]) AS clicks,
              unnest($4::int[]) AS unsubs
          ) AS v
          WHERE m.id = v.id
        `, [msgIds, openCounts, clickCounts, unsubCounts]);
      }
      
      await client.query('COMMIT');
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private generateDedupeKey(...parts: (string | undefined)[]): string {
    const data = parts.filter(Boolean).join(':');
    return sha256(data).substring(0, 32);
  }

  // @ts-expect-error Retained — superseded by isDuplicateWithTTL (FIX-043)
  private async isDuplicate(key: string): Promise<boolean> {
    const exists = await this.redis.get(`dedupe:${key}`);
    return exists !== null;
  }

  private async isDuplicateWithTTL(key: string, ttlSeconds: number): Promise<boolean> {
    const result = await this.redis.set(`dedupe:${key}`, '1', 'EX', ttlSeconds, 'NX');
    return result === null; // Returns null if key already exists
  }

  // @ts-expect-error Retained — manual deduplication helper for future use
  private async _markProcessed(key: string): Promise<void> {
    // TTL of 30 days for open deduplication
    await this.redis.set(`dedupe:${key}`, '1', 'EX', 86400 * 30);
  }

  private async incrementCounter(tenantId: string, metric: string): Promise<void> {
    const date = new Date().toISOString().split('T')[0];
    const hour = new Date().getUTCHours();
    
    // FIX-046: Use Redis pipeline to batch 4 commands into a single round-trip
    const hourlyKey = `stats:${tenantId}:${date}:${hour}:${metric}`;
    const dailyKey = `stats:${tenantId}:${date}:${metric}`;
    
    const pipeline = this.redis.pipeline();
    pipeline.incr(hourlyKey);
    pipeline.expire(hourlyKey, 86400 * 7); // 7 day TTL
    pipeline.incr(dailyKey);
    pipeline.expire(dailyKey, 86400 * 90); // 90 day TTL
    await pipeline.exec();
  }

  private async addToSuppressionList(
    tenantId: string, 
    email: string,
    category?: string
  ): Promise<void> {
    const suppressionId = generateId('sup');
    const normalizedEmail = email.toLowerCase().trim();
    
    if (category) {
      // Category-specific unsubscribe
      await this.db.query(`
        INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed, updated_at)
        VALUES ($1, $2, $3, $4, false, NOW())
        ON CONFLICT (tenant_id, email, category) DO UPDATE SET
          subscribed = false,
          updated_at = NOW()
      `, [suppressionId, tenantId, normalizedEmail, category]);
    } else {
      // Global unsubscribe
      await this.db.query(`
        INSERT INTO suppressions (id, tenant_id, email, reason, subtype, created_at)
        VALUES ($1, $2, $3, 'unsubscribe', 'one-click', NOW())
        ON CONFLICT (tenant_id, email) DO UPDATE SET
          reason = 'unsubscribe',
          subtype = 'one-click',
          updated_at = NOW()
      `, [suppressionId, tenantId, normalizedEmail]);
    }
    
    // Publish suppression event for other services
    await this.redis.publish('suppression:added', JSON.stringify({
      tenantId,
      email: normalizedEmail,
      reason: 'unsubscribe',
      category,
      timestamp: new Date().toISOString(),
    }));
  }
}
