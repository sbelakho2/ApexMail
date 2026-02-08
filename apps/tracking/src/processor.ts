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
  // FIX-500-348: Removed redundant 'tracking:' — Redis keyPrefix 'tracking:' auto-prepends
  private static readonly REDIS_WAL_KEY = 'apexmail:events:pending';

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
  private drainCommandRegistered = false;

  constructor(options: EventProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.logger = options.logger;
    this.flushIntervalMs = options.flushIntervalMs ?? 1000;
    this.maxBufferSize = options.maxBufferSize ?? 100;

    // FIX-068: Register custom command so ioredis uses EVALSHA (sends only the
    // SHA1 hash after the first call) instead of sending the full script text
    // on every eval() invocation.
    if (!this.drainCommandRegistered) {
      this.redis.defineCommand('atomicDrain', {
        numberOfKeys: 1,
        lua: EventProcessor.ATOMIC_DRAIN_SCRIPT,
      });
      this.drainCommandRegistered = true;
    }
  }

  start(): void {
    this.logger.info('Starting event processor', {
      flushIntervalMs: this.flushIntervalMs,
      maxBufferSize: this.maxBufferSize,
    });
    
    // FIX-500-120: Use setTimeout with re-scheduling instead of a fixed
    // interval timer. A fixed interval fires even while a flush is in
    // progress, wasting the tick (the flushing flag prevents re-entry).
    this.scheduleFlush();
  }

  /**
   * FIX-500-120: Schedule next flush after the current one completes.
   * Prevents timer-triggered flushes from overlapping with in-progress ones.
   */
  private scheduleFlush(): void {
    this.flushTimer = setTimeout(async () => {
      try {
        await this.flush();
      } catch (err) {
        this.logger.error('Flush error', { error: err instanceof Error ? err.message : 'Unknown' });
      }
      // Re-schedule only if not stopped
      if (this.flushTimer !== null) {
        this.scheduleFlush();
      }
    }, this.flushIntervalMs);
  }

  async stop(): Promise<void> {
    if (this.flushTimer) {
      // FIX-500-120: Use clearTimeout (was clearInterval)
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    
    // C-093: Drain ALL remaining events from Redis WAL, not just one batch.
    // flush() only drains up to maxBufferSize events per call, so we loop
    // until the WAL is empty to avoid leaving events behind on shutdown.
    let remaining = await this.redis.llen(EventProcessor.REDIS_WAL_KEY);
    while (remaining > 0) {
      this.logger.info('Draining Redis WAL on shutdown', { remaining });
      await this.flush();
      const newRemaining = await this.redis.llen(EventProcessor.REDIS_WAL_KEY);
      if (newRemaining >= remaining) {
        // No progress — avoid infinite loop (e.g. persistent parse errors)
        this.logger.warn('WAL drain stalled, exiting flush loop', { remaining: newRemaining });
        break;
      }
      remaining = newRemaining;
    }
    
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
    // C-109: TTL reduced from 30 days to 24 hours. A 30-day window wastes
    // Redis memory (~100 bytes × millions of messages) and provides minimal
    // dedup benefit — email clients that re-fetch tracking pixels do so
    // within a single session, not weeks later.
    const isNew = await this.redis.set(`dedupe:${dedupeKey}`, '1', 'EX', 86400, 'NX');
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
    
    // C-090: Pipeline enqueue + counter increment — they are independent and
    // can be batched into a single Redis round-trip.
    // E-174: Wrap in versioned envelope with checksum for integrity checking.
    // FIX-069: Reuse single Date object instead of creating 3
    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const hour = now.getUTCHours();
    const hourlyKey = `stats:${data.tenantId}:${date}:${hour}:opens`;
    const dailyKey = `stats:${data.tenantId}:${date}:opens`;

    // FIX-065: Single serialization — construct envelope via string concatenation
    // instead of JSON.stringify(event) + JSON.stringify({...d: event}) which serializes twice
    const payload = JSON.stringify(event);
    const cs = sha256(payload).slice(0, 8);
    const envelope = `{"v":${EventProcessor.WAL_VERSION},"cs":"${cs}","d":${payload}}`;

    const pipeline = this.redis.pipeline();
    pipeline.rpush(EventProcessor.REDIS_WAL_KEY, envelope);
    pipeline.incr(hourlyKey);
    pipeline.expire(hourlyKey, 86400 * 7);
    pipeline.incr(dailyKey);
    pipeline.expire(dailyKey, 86400 * 90);
    await pipeline.exec();
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
    
    // FIX-064: Consolidate 4 sequential Redis round-trips into a single pipeline.
    // Previously: enqueueEvent (RPUSH), incrementCounter (pipeline), SET NX EX,
    // conditional incrementCounter — each awaited sequentially.
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    const hour = now.getUTCHours();
    const hourlyKey = `stats:${data.tenantId}:${dateStr}:${hour}:clicks`;
    const dailyKey = `stats:${data.tenantId}:${dateStr}:clicks`;
    const uniqueKey = `unique_click:${data.tenantId}:${data.messageId}:${data.linkId}`;

    const payload = JSON.stringify(event);
    // FIX-065: Single serialization — construct envelope via string concat
    const cs = sha256(payload).slice(0, 8);
    const envelope = `{"v":${EventProcessor.WAL_VERSION},"cs":"${cs}","d":${payload}}`;

    const pipeline = this.redis.pipeline();
    pipeline.rpush(EventProcessor.REDIS_WAL_KEY, envelope);
    pipeline.incr(hourlyKey);
    pipeline.expire(hourlyKey, 86400 * 7);
    pipeline.incr(dailyKey);
    pipeline.expire(dailyKey, 86400 * 90);
    pipeline.set(uniqueKey, '1', 'EX', 86400 * 30, 'NX');
    const results = await pipeline.exec();

    // Check if unique click (SET NX returns 'OK' if set, null if existed)
    const isFirstClick = results?.[5]?.[1] === 'OK';
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
   * E-174: WAL envelope version for forward-compatible integrity checking.
   * Every entry written to Redis is wrapped with a version tag so the
   * flush loop can detect and skip entries from incompatible formats.
   */
  private static readonly WAL_VERSION = 1;

  /**
   * Enqueue event into Redis WAL for durable buffering.
   * The event is persisted in Redis BEFORE the HTTP response is returned,
   * so it survives process crashes. The flush loop drains Redis → Postgres.
   *
   * E-174: Events are wrapped in a versioned envelope with a checksum
   * so the flush loop can detect corrupted or incompatible entries.
   */
  private async enqueueEvent(event: TrackingEvent): Promise<void> {
    // FIX-065: Single serialization — use string concat instead of nested JSON.stringify
    const payload = JSON.stringify(event);
    const cs = sha256(payload).slice(0, 8); // 8-char checksum prefix (collision-resistant enough for corruption detection)
    const envelope = `{"v":${EventProcessor.WAL_VERSION},"cs":"${cs}","d":${payload}}`;
    await this.redis.rpush(
      EventProcessor.REDIS_WAL_KEY,
      envelope
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
      // FIX-068: Use defineCommand's EVALSHA instead of raw eval
      const rawEvents = await (this.redis as any).atomicDrain(
        EventProcessor.REDIS_WAL_KEY,
        this.maxBufferSize.toString()
      ) as string[];
      
      if (!rawEvents || rawEvents.length === 0) {
        return;
      }

      // Parse events from Redis
      // E-174: Support both versioned envelopes (v1+) and legacy bare events
      const eventsToFlush: TrackingEvent[] = [];
      for (const raw of rawEvents) {
        try {
          const outer = JSON.parse(raw);

          let event: TrackingEvent;
          if (outer.v !== undefined && outer.d !== undefined) {
            // Versioned envelope — verify checksum
            if (outer.v !== EventProcessor.WAL_VERSION) {
              this.logger.warn('Skipping WAL entry with unsupported version', { version: outer.v });
              continue;
            }
            // FIX-066: Extract raw JSON payload from envelope string to avoid
            // re-serializing the parsed object (which is expensive and may produce
            // different key ordering than the original).
            const dIdx = raw.indexOf(',"d":');
            const rawPayload = dIdx !== -1 ? raw.slice(dIdx + 5, raw.length - 1) : JSON.stringify(outer.d);
            const expectedCs = sha256(rawPayload).slice(0, 8);
            if (outer.cs !== expectedCs) {
              this.logger.warn('WAL entry checksum mismatch — data may be corrupted, skipping', {
                expected: expectedCs,
                actual: outer.cs,
              });
              continue;
            }
            event = outer.d as TrackingEvent;
          } else {
            // Legacy bare event (written before E-174) — accept as-is
            event = outer as TrackingEvent;
          }

          // Restore Date object from JSON serialization
          event.timestamp = new Date(event.timestamp);
          eventsToFlush.push(event);
        } catch {
          this.logger.warn('Failed to parse event from Redis WAL, skipping', { raw: raw.slice(0, 100) });
        }
      }

      if (eventsToFlush.length > 0) {
        try {
          await this.writeEvents(eventsToFlush);
        } catch (writeError) {
          // FIX-500-001: Re-push drained events back to Redis WAL on write failure.
          // The atomic Lua drain already removed them from Redis, so if Postgres
          // is down the events would be permanently lost. Re-enqueue them so
          // the next flush cycle retries.
          this.logger.error('writeEvents failed — re-pushing events to Redis WAL', {
            count: eventsToFlush.length,
            error: writeError instanceof Error ? writeError.message : 'Unknown',
          });
          const pipeline = this.redis.pipeline();
          for (const evt of eventsToFlush) {
            // FIX-065/066: Single serialization via string concat
            const payload = JSON.stringify(evt);
            const cs = sha256(payload).slice(0, 8);
            const envelope = `{"v":${EventProcessor.WAL_VERSION},"cs":"${cs}","d":${payload}}`;
            pipeline.rpush(EventProcessor.REDIS_WAL_KEY, envelope);
          }
          await pipeline.exec().catch(rePushErr => {
            this.logger.error('CRITICAL: Failed to re-push events to Redis WAL — events may be lost', {
              count: eventsToFlush.length,
              error: rePushErr instanceof Error ? rePushErr.message : 'Unknown',
            });
          });
          throw writeError; // Propagate so caller sees the failure
        }
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
    let hasError = false;
    try {
      await client.query('BEGIN');
      
      // Batch insert events
      // FIX-500-483: Guard against PG's ~65535 param limit by chunking
      const PARAMS_PER_EVENT = 10;
      const MAX_EVENTS_PER_CHUNK = Math.floor(65000 / PARAMS_PER_EVENT); // 6500
      
      for (let chunkStart = 0; chunkStart < events.length; chunkStart += MAX_EVENTS_PER_CHUNK) {
        const chunk = events.slice(chunkStart, chunkStart + MAX_EVENTS_PER_CHUNK);
        const values: unknown[] = [];
        const placeholders: string[] = [];
        let paramIndex = 1;
      
        for (const event of chunk) {
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
      } // end chunk loop
      
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
      hasError = true;
      throw error;
    } finally {
      // FIX-500-482: Destroy connection on error to avoid returning a
      // potentially corrupted connection to the pool
      client.release(hasError);
    }
  }

  private generateDedupeKey(...parts: (string | undefined)[]): string {
    const data = parts.filter(Boolean).join(':');
    return sha256(data).substring(0, 32);
  }

  // FIX-500-136: Removed dead isDuplicate — superseded by isDuplicateWithTTL (FIX-043)

  private async isDuplicateWithTTL(key: string, ttlSeconds: number): Promise<boolean> {
    const result = await this.redis.set(`dedupe:${key}`, '1', 'EX', ttlSeconds, 'NX');
    return result === null; // Returns null if key already exists
  }

  // FIX-500-137: Removed dead _markProcessed — isDuplicateWithTTL already sets
  // the dedupe key atomically via SET ... NX, making this redundant.

  private async incrementCounter(tenantId: string, metric: string): Promise<void> {
    // FIX-070: Reuse single Date object instead of creating 2
    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const hour = now.getUTCHours();
    
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
    // F-217: Fire-and-forget — don't block unsubscribe flow for Redis publish
    this.redis.publish('suppression:added', JSON.stringify({
      tenantId,
      email: normalizedEmail,
      reason: 'unsubscribe',
      category,
      timestamp: new Date().toISOString(),
    })).catch((err) => {
      this.logger.error('Failed to publish suppression event', { error: err instanceof Error ? err.message : 'Unknown' });
    });
  }
}
