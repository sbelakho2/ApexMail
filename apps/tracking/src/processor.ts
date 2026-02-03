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
  // SECURITY: Hard cap to prevent unbounded memory growth during flush
  private readonly absoluteMaxBufferSize: number;
  
  private buffer: TrackingEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private flushing = false;
  // Track dropped events for monitoring
  private droppedEventCount = 0;

  constructor(options: EventProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.logger = options.logger;
    this.flushIntervalMs = options.flushIntervalMs ?? 1000;
    this.maxBufferSize = options.maxBufferSize ?? 100;
    // Hard cap at 10x normal buffer size to prevent OOM
    this.absoluteMaxBufferSize = this.maxBufferSize * 10;
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
    // Dedupe: Check if this exact open was already recorded
    const dedupeKey = this.generateDedupeKey('open', data.messageId, data.recipient);
    
    if (await this.isDuplicate(dedupeKey)) {
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
    
    this.addToBuffer(event);
    
    // Mark as processed
    await this.markProcessed(dedupeKey);
    
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
    
    this.addToBuffer(event);
    
    // Update Redis real-time counter
    await this.incrementCounter(data.tenantId, 'clicks');
    
    // Also record unique clicks
    const uniqueKey = `unique_click:${data.tenantId}:${data.messageId}:${data.linkId}`;
    const isFirstClick = await this.redis.setnx(uniqueKey, '1');
    if (isFirstClick) {
      await this.redis.expire(uniqueKey, 86400 * 30); // 30 day TTL
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
    
    this.addToBuffer(event);
    
    // Update Redis real-time counter
    await this.incrementCounter(data.tenantId, 'unsubscribes');
    
    // Add to suppression list immediately
    await this.addToSuppressionList(data.tenantId, data.recipient, data.category);
  }

  private addToBuffer(event: TrackingEvent): void {
    // SECURITY: Enforce hard cap to prevent unbounded memory growth
    // This can happen when flush is slow or failing and events keep arriving
    if (this.buffer.length >= this.absoluteMaxBufferSize) {
      this.droppedEventCount++;
      // Log every 100 dropped events to avoid log spam
      if (this.droppedEventCount % 100 === 1) {
        this.logger.error('Buffer overflow - dropping events', {
          droppedTotal: this.droppedEventCount,
          bufferSize: this.buffer.length,
          maxSize: this.absoluteMaxBufferSize,
          flushing: this.flushing,
        });
      }
      return; // Drop the event to prevent OOM
    }

    this.buffer.push(event);
    
    // Flush if buffer is full
    if (this.buffer.length >= this.maxBufferSize && !this.flushing) {
      this.flush().catch(err => {
        this.logger.error('Flush error', { error: err instanceof Error ? err.message : 'Unknown' });
      });
    }
  }

  private async flush(): Promise<void> {
    if (this.buffer.length === 0 || this.flushing) {
      return;
    }
    
    this.flushing = true;
    const eventsToFlush = [...this.buffer];
    this.buffer = [];
    
    try {
      await this.writeEvents(eventsToFlush);
      this.logger.debug('Flushed events', { count: eventsToFlush.length });
    } catch (error) {
      // Put events back in buffer on failure
      this.buffer = [...eventsToFlush, ...this.buffer];
      this.logger.error('Failed to flush events', { 
        error: error instanceof Error ? error.message : 'Unknown',
        count: eventsToFlush.length,
      });
      throw error;
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
      
      // Update message stats in batch
      const messageUpdates = new Map<string, { opens: number; clicks: number; unsubscribes: number }>();
      
      for (const event of events) {
        const key = event.messageId;
        const stats = messageUpdates.get(key) ?? { opens: 0, clicks: 0, unsubscribes: 0 };
        
        if (event.type === 'opened') stats.opens++;
        else if (event.type === 'clicked') stats.clicks++;
        else if (event.type === 'unsubscribed') stats.unsubscribes++;
        
        messageUpdates.set(key, stats);
      }
      
      for (const [messageId, stats] of messageUpdates) {
        if (stats.opens > 0 || stats.clicks > 0 || stats.unsubscribes > 0) {
          await client.query(`
            UPDATE messages SET
              open_count = open_count + $1,
              click_count = click_count + $2,
              unsubscribe_count = unsubscribe_count + $3,
              first_opened_at = COALESCE(first_opened_at, CASE WHEN $1 > 0 THEN NOW() END),
              first_clicked_at = COALESCE(first_clicked_at, CASE WHEN $2 > 0 THEN NOW() END),
              updated_at = NOW()
            WHERE id = $4
          `, [stats.opens, stats.clicks, stats.unsubscribes, messageId]);
        }
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

  private async isDuplicate(key: string): Promise<boolean> {
    const exists = await this.redis.get(`dedupe:${key}`);
    return exists !== null;
  }

  private async isDuplicateWithTTL(key: string, ttlSeconds: number): Promise<boolean> {
    const result = await this.redis.set(`dedupe:${key}`, '1', 'EX', ttlSeconds, 'NX');
    return result === null; // Returns null if key already exists
  }

  private async markProcessed(key: string): Promise<void> {
    // TTL of 30 days for open deduplication
    await this.redis.set(`dedupe:${key}`, '1', 'EX', 86400 * 30);
  }

  private async incrementCounter(tenantId: string, metric: string): Promise<void> {
    const date = new Date().toISOString().split('T')[0];
    const hour = new Date().getUTCHours();
    
    // Hourly counter
    const hourlyKey = `stats:${tenantId}:${date}:${hour}:${metric}`;
    await this.redis.incr(hourlyKey);
    await this.redis.expire(hourlyKey, 86400 * 7); // 7 day TTL
    
    // Daily counter
    const dailyKey = `stats:${tenantId}:${date}:${metric}`;
    await this.redis.incr(dailyKey);
    await this.redis.expire(dailyKey, 86400 * 90); // 90 day TTL
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
