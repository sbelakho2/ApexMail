/**
 * Events Repository - Immutable event log with deduplication
 * Handles all email lifecycle events: sent, delivered, bounced, opened, clicked, unsubscribed, complained
 */

import { createHash } from 'node:crypto';
import { Result, parseJsonOrDefault } from '@apexmail/lib';
import { generateUuid } from '@apexmail/lib/id';
import type { DatabasePool } from '../pool.js';

export type EventType =
  | 'queued'
  | 'sending'
  | 'sent'
  | 'deferred'
  | 'delivered'
  | 'bounced'
  | 'dropped'
  | 'opened'
  | 'clicked'
  | 'unsubscribed'
  | 'complained'
  | 'list_unsubscribe';

export interface Event {
  id: string;
  tenantId: string;
  messageId: string;
  recipientEmail: string;
  recipientEmailHash: string;
  eventType: EventType;
  timestamp: Date;
  ipAddress: string | null;
  userAgent: string | null;
  deviceType: string | null;
  location: EventLocation | null;
  linkUrl: string | null;
  linkId: string | null;
  bounceType: 'hard' | 'soft' | null;
  bounceCode: string | null;
  bounceReason: string | null;
  feedbackType: string | null;
  mtaResponse: string | null;
  rawPayload: Record<string, unknown> | null;
  deduplicationKey: string;
  processedAt: Date;
  metadata: Record<string, unknown>;
}

export interface EventLocation {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
}

export interface CreateEventInput {
  tenantId: string;
  messageId: string;
  recipientEmail: string;
  eventType: EventType;
  timestamp?: Date;
  ipAddress?: string;
  userAgent?: string;
  deviceType?: string;
  location?: EventLocation;
  linkUrl?: string;
  linkId?: string;
  bounceType?: 'hard' | 'soft';
  bounceCode?: string;
  bounceReason?: string;
  feedbackType?: string;
  mtaResponse?: string;
  rawPayload?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface EventStats {
  sent: number;
  delivered: number;
  bounced: number;
  opened: number;
  clicked: number;
  unsubscribed: number;
  complained: number;
  uniqueOpens: number;
  uniqueClicks: number;
}

export class EventsRepository {
  constructor(private readonly db: DatabasePool) {}

  private hashEmail(email: string): string {
    const normalizedEmail = email.toLowerCase().trim();
    return createHash('sha256').update(normalizedEmail).digest('hex');
  }

  private generateDeduplicationKey(input: CreateEventInput): string {
    // Dedup key: message + recipient + event type + timestamp (minute precision for opens/clicks)
    const timestampStr = input.eventType === 'opened' || input.eventType === 'clicked'
      ? new Date(input.timestamp ?? Date.now()).toISOString().slice(0, 16) // Minute precision
      : new Date(input.timestamp ?? Date.now()).toISOString();
    
    const components = [
      input.messageId,
      input.recipientEmail.toLowerCase().trim(),
      input.eventType,
      timestampStr,
      input.linkUrl ?? '',
    ];
    
    return createHash('sha256').update(components.join('|')).digest('hex');
  }

  async create(input: CreateEventInput): Promise<Result<Event | null, Error>> {
    const id = generateUuid();
    const emailHash = this.hashEmail(input.recipientEmail);
    const deduplicationKey = this.generateDeduplicationKey(input);
    const now = new Date();
    const timestamp = input.timestamp ?? now;

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      message_id: string;
      recipient_email: string;
      recipient_email_hash: string;
      event_type: EventType;
      timestamp: Date;
      ip_address: string | null;
      user_agent: string | null;
      device_type: string | null;
      location: string | null;
      link_url: string | null;
      link_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      bounce_reason: string | null;
      feedback_type: string | null;
      mta_response: string | null;
      raw_payload: string | null;
      deduplication_key: string;
      processed_at: Date;
      metadata: string;
    }>(
      `INSERT INTO events (
        id, tenant_id, message_id, recipient_email, recipient_email_hash,
        event_type, timestamp, ip_address, user_agent, device_type,
        location, link_url, link_id, bounce_type, bounce_code,
        bounce_reason, feedback_type, mta_response, raw_payload,
        deduplication_key, processed_at, metadata
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
        $16, $17, $18, $19, $20, $21, $22
      )
      ON CONFLICT (deduplication_key) DO NOTHING
      RETURNING *`,
      [
        id,
        input.tenantId,
        input.messageId,
        input.recipientEmail.toLowerCase().trim(),
        emailHash,
        input.eventType,
        timestamp,
        input.ipAddress ?? null,
        input.userAgent ?? null,
        input.deviceType ?? null,
        input.location ? JSON.stringify(input.location) : null,
        input.linkUrl ?? null,
        input.linkId ?? null,
        input.bounceType ?? null,
        input.bounceCode ?? null,
        input.bounceReason ?? null,
        input.feedbackType ?? null,
        input.mtaResponse ?? null,
        input.rawPayload ? JSON.stringify(input.rawPayload) : null,
        deduplicationKey,
        now,
        JSON.stringify(input.metadata ?? {}),
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    // Returns null if deduplicated (already exists)
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async createBulk(inputs: CreateEventInput[]): Promise<Result<{ created: number; duplicates: number }, Error>> {
    if (inputs.length === 0) {
      return Result.ok({ created: 0, duplicates: 0 });
    }

    const now = new Date();
    const values: unknown[] = [];
    const placeholders: string[] = [];
    let paramIndex = 1;

    for (const input of inputs) {
      const id = generateUuid();
      const emailHash = this.hashEmail(input.recipientEmail);
      const deduplicationKey = this.generateDeduplicationKey(input);
      const timestamp = input.timestamp ?? now;

      placeholders.push(
        `($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`
      );
      values.push(
        id,
        input.tenantId,
        input.messageId,
        input.recipientEmail.toLowerCase().trim(),
        emailHash,
        input.eventType,
        timestamp,
        input.ipAddress ?? null,
        input.userAgent ?? null,
        input.deviceType ?? null,
        input.location ? JSON.stringify(input.location) : null,
        input.linkUrl ?? null,
        input.linkId ?? null,
        input.bounceType ?? null,
        input.bounceCode ?? null,
        input.bounceReason ?? null,
        input.feedbackType ?? null,
        input.mtaResponse ?? null,
        input.rawPayload ? JSON.stringify(input.rawPayload) : null,
        deduplicationKey,
        now,
        JSON.stringify(input.metadata ?? {})
      );
    }

    const result = await this.db.query<{ inserted: string }>(
      `WITH inserted AS (
        INSERT INTO events (
          id, tenant_id, message_id, recipient_email, recipient_email_hash,
          event_type, timestamp, ip_address, user_agent, device_type,
          location, link_url, link_id, bounce_type, bounce_code,
          bounce_reason, feedback_type, mta_response, raw_payload,
          deduplication_key, processed_at, metadata
        ) VALUES ${placeholders.join(', ')}
        ON CONFLICT (deduplication_key) DO NOTHING
        RETURNING 1
      ) SELECT COUNT(*) as inserted FROM inserted`,
      values
    );

    if (!result.ok) return result;

    const created = parseInt(result.value.rows[0]?.inserted ?? '0', 10);
    return Result.ok({
      created,
      duplicates: inputs.length - created,
    });
  }

  async findById(id: string, tenantId?: string): Promise<Result<Event | null, Error>> {
    const query = tenantId
      ? 'SELECT * FROM events WHERE id = $1 AND tenant_id = $2'
      : 'SELECT * FROM events WHERE id = $1';
    const params = tenantId ? [id, tenantId] : [id];
    
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      message_id: string;
      recipient_email: string;
      recipient_email_hash: string;
      event_type: EventType;
      timestamp: Date;
      ip_address: string | null;
      user_agent: string | null;
      device_type: string | null;
      location: string | null;
      link_url: string | null;
      link_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      bounce_reason: string | null;
      feedback_type: string | null;
      mta_response: string | null;
      raw_payload: string | null;
      deduplication_key: string;
      processed_at: Date;
      metadata: string;
    }>(query, params);

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByMessageId(messageId: string, tenantId?: string, options?: { limit?: number }): Promise<Result<Event[], Error>> {
    // FIX-500-046: Add LIMIT to prevent unbounded result sets
    const limit = options?.limit ?? 1000;
    const query = tenantId
      ? 'SELECT * FROM events WHERE message_id = $1 AND tenant_id = $2 ORDER BY timestamp LIMIT $3'
      : 'SELECT * FROM events WHERE message_id = $1 ORDER BY timestamp LIMIT $2';
    const params = tenantId ? [messageId, tenantId, limit] : [messageId, limit];
    
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      message_id: string;
      recipient_email: string;
      recipient_email_hash: string;
      event_type: EventType;
      timestamp: Date;
      ip_address: string | null;
      user_agent: string | null;
      device_type: string | null;
      location: string | null;
      link_url: string | null;
      link_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      bounce_reason: string | null;
      feedback_type: string | null;
      mta_response: string | null;
      raw_payload: string | null;
      deduplication_key: string;
      processed_at: Date;
      metadata: string;
    }>(query, params);

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async listByTenant(
    tenantId: string,
    options: {
      eventType?: EventType;
      startDate?: Date;
      endDate?: Date;
      messageId?: string;
      recipientEmail?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Result<{ events: Event[]; total: number }, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.eventType) {
      conditions.push(`event_type = $${paramIndex++}`);
      values.push(options.eventType);
    }
    if (options.startDate) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      values.push(options.startDate);
    }
    if (options.endDate) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      values.push(options.endDate);
    }
    if (options.messageId) {
      conditions.push(`message_id = $${paramIndex++}`);
      values.push(options.messageId);
    }
    if (options.recipientEmail) {
      conditions.push(`recipient_email_hash = $${paramIndex++}`);
      values.push(this.hashEmail(options.recipientEmail));
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // FIX-500-044: Use COUNT(*) OVER() to combine count and data in a single query
    // FIX-500-049: Functional index idx_events_recipient_domain added in migration 010_performance_indexes.sql
    const limit = options.limit ?? 100;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      message_id: string;
      recipient_email: string;
      recipient_email_hash: string;
      event_type: EventType;
      timestamp: Date;
      ip_address: string | null;
      user_agent: string | null;
      device_type: string | null;
      location: string | null;
      link_url: string | null;
      link_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      bounce_reason: string | null;
      feedback_type: string | null;
      mta_response: string | null;
      raw_payload: string | null;
      deduplication_key: string;
      processed_at: Date;
      metadata: string;
      total_count: string;
    }>(
      `SELECT *, COUNT(*) OVER() AS total_count FROM events ${whereClause}
       ORDER BY timestamp DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      events: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(result.value.rows[0]?.total_count ?? '0', 10),
    });
  }

  async getStats(
    tenantId: string,
    options: {
      startDate?: Date;
      endDate?: Date;
      since?: Date;
      until?: Date;
      campaignId?: string;
    } = {}
  ): Promise<Result<EventStats, Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['e.tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`e.timestamp >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`e.timestamp <= $${paramIndex++}`);
      values.push(endDate);
    }

    let joinClause = '';
    if (options.campaignId) {
      joinClause = 'JOIN messages m ON e.message_id = m.id';
      conditions.push(`m.campaign_id = $${paramIndex++}`);
      values.push(options.campaignId);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      event_type: EventType;
      total: string;
      unique_recipients: string;
    }>(
      `SELECT 
        e.event_type,
        COUNT(*) as total,
        COUNT(DISTINCT e.recipient_email_hash) as unique_recipients
       FROM events e
       ${joinClause}
       ${whereClause}
       GROUP BY e.event_type`,
      values
    );

    if (!result.ok) return result;

    const stats: EventStats = {
      sent: 0,
      delivered: 0,
      bounced: 0,
      opened: 0,
      clicked: 0,
      unsubscribed: 0,
      complained: 0,
      uniqueOpens: 0,
      uniqueClicks: 0,
    };

    for (const row of result.value.rows) {
      const total = parseInt(row.total, 10);
      const unique = parseInt(row.unique_recipients, 10);

      switch (row.event_type) {
        case 'sent':
          stats.sent = total;
          break;
        case 'delivered':
          stats.delivered = total;
          break;
        case 'bounced':
          stats.bounced = total;
          break;
        case 'opened':
          stats.opened = total;
          stats.uniqueOpens = unique;
          break;
        case 'clicked':
          stats.clicked = total;
          stats.uniqueClicks = unique;
          break;
        case 'unsubscribed':
        case 'list_unsubscribe':
          stats.unsubscribed += total;
          break;
        case 'complained':
          stats.complained = total;
          break;
      }
    }

    return Result.ok(stats);
  }

  async getTimeSeriesStats(
    tenantId: string,
    options: {
      startDate: Date;
      endDate: Date;
      granularity: 'hour' | 'day' | 'week';
      eventTypes?: EventType[];
    }
  ): Promise<Result<{ timestamp: Date; eventType: EventType; count: number }[], Error>> {
    const truncFn = options.granularity === 'hour'
      ? 'hour'
      : options.granularity === 'day'
        ? 'day'
        : 'week';

    const conditions = ['tenant_id = $1', 'timestamp >= $2', 'timestamp <= $3'];
    const values: unknown[] = [tenantId, options.startDate, options.endDate];
    let paramIndex = 4;

    if (options.eventTypes && options.eventTypes.length > 0) {
      conditions.push(`event_type = ANY($${paramIndex++})`);
      values.push(options.eventTypes);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      bucket: Date;
      event_type: EventType;
      count: string;
    }>(
      `SELECT 
        DATE_TRUNC('${truncFn}', timestamp) as bucket,
        event_type,
        COUNT(*) as count
       FROM events
       ${whereClause}
       GROUP BY bucket, event_type
       ORDER BY bucket, event_type`,
      values
    );

    if (!result.ok) return result;

    return Result.ok(
      result.value.rows.map((row) => ({
        timestamp: row.bucket,
        eventType: row.event_type,
        count: parseInt(row.count, 10),
      }))
    );
  }

  async getLinkStats(
    messageId: string,
    tenantId?: string
  ): Promise<Result<{ linkUrl: string; clicks: number; uniqueClicks: number }[], Error>> {
    // SECURITY: When tenantId provided, filter by tenant to prevent cross-tenant data leak
    const query = tenantId
      ? `SELECT 
          link_url,
          COUNT(*) as clicks,
          COUNT(DISTINCT recipient_email_hash) as unique_clicks
         FROM events
         WHERE message_id = $1 AND tenant_id = $2 AND event_type = 'clicked' AND link_url IS NOT NULL
         GROUP BY link_url
         ORDER BY clicks DESC`
      : `SELECT 
          link_url,
          COUNT(*) as clicks,
          COUNT(DISTINCT recipient_email_hash) as unique_clicks
         FROM events
         WHERE message_id = $1 AND event_type = 'clicked' AND link_url IS NOT NULL
         GROUP BY link_url
         ORDER BY clicks DESC`;
    const params = tenantId ? [messageId, tenantId] : [messageId];
    
    const result = await this.db.query<{
      link_url: string;
      clicks: string;
      unique_clicks: string;
    }>(
      query,
      params
    );

    if (!result.ok) return result;

    return Result.ok(
      result.value.rows.map((row) => ({
        linkUrl: row.link_url,
        clicks: parseInt(row.clicks, 10),
        uniqueClicks: parseInt(row.unique_clicks, 10),
      }))
    );
  }

  async archiveOldEvents(olderThanDays: number): Promise<Result<number, Error>> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const result = await this.db.query<{ count: string }>(
      `WITH deleted AS (
          DELETE FROM events
          WHERE timestamp < $1
          RETURNING id
       )
       SELECT COUNT(*)::text as count FROM deleted`,
      [cutoffDate]
    );

    if (!result.ok) return result;

    return Result.ok(parseInt(result.value.rows[0]?.count ?? '0', 10));
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    message_id: string;
    recipient_email: string;
    recipient_email_hash: string;
    event_type: EventType;
    timestamp: Date;
    ip_address: string | null;
    user_agent: string | null;
    device_type: string | null;
    location: string | null;
    link_url: string | null;
    link_id: string | null;
    bounce_type: 'hard' | 'soft' | null;
    bounce_code: string | null;
    bounce_reason: string | null;
    feedback_type: string | null;
    mta_response: string | null;
    raw_payload: string | null;
    deduplication_key: string;
    processed_at: Date;
    metadata: string;
  }): Event {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      messageId: row.message_id,
      recipientEmail: row.recipient_email,
      recipientEmailHash: row.recipient_email_hash,
      eventType: row.event_type,
      timestamp: row.timestamp,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      deviceType: row.device_type,
      location: row.location
        ? (typeof row.location === 'string'
          ? parseJsonOrDefault<EventLocation>(row.location, null as unknown as EventLocation)
          : row.location) as EventLocation
        : null,
      linkUrl: row.link_url,
      linkId: row.link_id,
      bounceType: row.bounce_type,
      bounceCode: row.bounce_code,
      bounceReason: row.bounce_reason,
      feedbackType: row.feedback_type,
      mtaResponse: row.mta_response,
      rawPayload: row.raw_payload
        ? (typeof row.raw_payload === 'string'
          ? parseJsonOrDefault<Record<string, unknown>>(row.raw_payload, {})
          : row.raw_payload) as Record<string, unknown>
        : null,
      deduplicationKey: row.deduplication_key,
      processedAt: row.processed_at,
      metadata: typeof row.metadata === 'string'
        ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {})
        : row.metadata as unknown as Record<string, unknown>,
    };
  }

  /**
   * Get time series data for events aggregated per time bucket
   */
  async getTimeSeries(
    tenantId: string,
    options: {
      since?: Date;
      until?: Date;
      startDate?: Date;
      endDate?: Date;
      interval: 'minute' | 'hour' | 'day' | 'week' | 'month';
      domainId?: string;
      campaignId?: string;
      eventTypes?: EventType[];
    }
  ): Promise<Result<{
    timestamp: Date;
    delivered?: number;
    opened?: number;
    clicked?: number;
    unsubscribed?: number;
    complained?: number;
    bounced?: number;
    sent?: number;
  }[], Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['e.tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`e.timestamp >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`e.timestamp <= $${paramIndex++}`);
      values.push(endDate);
    }

    let joinClause = '';
    if (options.domainId) {
      joinClause = 'JOIN domains d ON e.tenant_id = d.tenant_id';
      conditions.push(`d.id = $${paramIndex++}`);
      values.push(options.domainId);
    }
    if (options.campaignId) {
      joinClause += joinClause ? ' ' : '';
      joinClause += 'JOIN messages m ON e.message_id = m.id';
      conditions.push(`m.campaign_id = $${paramIndex++}`);
      values.push(options.campaignId);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Map interval to PostgreSQL date_trunc format
    const truncInterval = options.interval === 'minute' ? 'hour' : options.interval;

    const result = await this.db.query<{
      bucket: Date;
      event_type: EventType;
      count: string;
    }>(
      `SELECT 
        DATE_TRUNC('${truncInterval}', e.timestamp) as bucket,
        e.event_type,
        COUNT(*) as count
       FROM events e
       ${joinClause}
       ${whereClause}
       GROUP BY bucket, e.event_type
       ORDER BY bucket ASC`,
      values
    );

    if (!result.ok) return result;

    // Aggregate by timestamp
    const byTimestamp = new Map<string, {
      timestamp: Date;
      delivered: number;
      opened: number;
      clicked: number;
      unsubscribed: number;
      complained: number;
      bounced: number;
      sent: number;
    }>();

    for (const row of result.value.rows) {
      const key = row.bucket.toISOString();
      const existing = byTimestamp.get(key) ?? {
        timestamp: row.bucket,
        delivered: 0,
        opened: 0,
        clicked: 0,
        unsubscribed: 0,
        complained: 0,
        bounced: 0,
        sent: 0,
      };
      const count = parseInt(row.count, 10);

      switch (row.event_type) {
        case 'delivered':
          existing.delivered += count;
          break;
        case 'opened':
          existing.opened += count;
          break;
        case 'clicked':
          existing.clicked += count;
          break;
        case 'unsubscribed':
        case 'list_unsubscribe':
          existing.unsubscribed += count;
          break;
        case 'complained':
          existing.complained += count;
          break;
        case 'bounced':
          existing.bounced += count;
          break;
        case 'sent':
          existing.sent += count;
          break;
      }

      byTimestamp.set(key, existing);
    }

    return Result.ok(Array.from(byTimestamp.values()));
  }

  /**
   * Get event statistics grouped by domain
   */
  async getStatsByDomain(
    tenantId: string,
    options: { startDate?: Date; endDate?: Date; since?: Date; until?: Date } = {}
  ): Promise<Result<{
    domainId: string;
    domainName: string;
    domain: string;
    sent: number;
    delivered: number;
    bounced: number;
    opened: number;
    clicked: number;
    complained: number;
  }[], Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['e.tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`e.timestamp >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`e.timestamp <= $${paramIndex++}`);
      values.push(endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      domain: string;
      event_type: EventType;
      count: string;
    }>(
      `SELECT 
        SPLIT_PART(e.recipient_email, '@', 2) as domain,
        e.event_type,
        COUNT(*) as count
       FROM events e
       ${whereClause}
       GROUP BY domain, e.event_type
       ORDER BY domain`,
      values
    );

    if (!result.ok) return result;

    // Aggregate by domain
    const byDomain = new Map<string, {
      sent: number;
      delivered: number;
      bounced: number;
      opened: number;
      clicked: number;
      complained: number;
    }>();

    for (const row of result.value.rows) {
      const domain = row.domain || 'unknown';
      const existing = byDomain.get(domain) ?? {
        sent: 0, delivered: 0, bounced: 0, opened: 0, clicked: 0, complained: 0,
      };
      const count = parseInt(row.count, 10);

      switch (row.event_type) {
        case 'sent':
          existing.sent += count;
          break;
        case 'delivered':
          existing.delivered += count;
          break;
        case 'bounced':
          existing.bounced += count;
          break;
        case 'opened':
          existing.opened += count;
          break;
        case 'clicked':
          existing.clicked += count;
          break;
        case 'complained':
          existing.complained += count;
          break;
      }

      byDomain.set(domain, existing);
    }

    return Result.ok(
      Array.from(byDomain.entries()).map(([domain, stats]) => ({
        domainId: domain, // Use domain as ID since we don't have a proper domain table join
        domainName: domain,
        domain,
        ...stats,
      }))
    );
  }

  /**
   * Get event statistics grouped by campaign
   */
  async getStatsByCampaign(
    tenantId: string,
    options: { startDate?: Date; endDate?: Date; since?: Date; until?: Date; limit?: number } = {}
  ): Promise<Result<{
    campaignId: string;
    sent: number;
    delivered: number;
    bounced: number;
    opened: number;
    clicked: number;
    unsubscribed: number;
    complained: number;
    openRate: number;
    clickRate: number;
    firstEvent: Date | null;
    lastEvent: Date | null;
  }[], Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['e.tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`e.timestamp >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`e.timestamp <= $${paramIndex++}`);
      values.push(endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      campaign_id: string;
      event_type: EventType;
      count: string;
      first_event: Date;
      last_event: Date;
    }>(
      `SELECT 
        m.campaign_id,
        e.event_type,
        COUNT(*) as count,
        MIN(e.timestamp) as first_event,
        MAX(e.timestamp) as last_event
       FROM events e
       JOIN messages m ON e.message_id = m.id
       ${whereClause}
         AND m.campaign_id IS NOT NULL
       GROUP BY m.campaign_id, e.event_type
       ORDER BY m.campaign_id`,
      values
    );

    if (!result.ok) return result;

    // Aggregate by campaign
    const byCampaign = new Map<string, {
      sent: number;
      delivered: number;
      bounced: number;
      opened: number;
      clicked: number;
      unsubscribed: number;
      complained: number;
      firstEvent: Date | null;
      lastEvent: Date | null;
    }>();

    for (const row of result.value.rows) {
      const campaignId = row.campaign_id;
      const existing = byCampaign.get(campaignId) ?? {
        sent: 0, delivered: 0, bounced: 0, opened: 0, clicked: 0, unsubscribed: 0, complained: 0,
        firstEvent: null, lastEvent: null,
      };
      const count = parseInt(row.count, 10);

      // Update first/last event times
      if (!existing.firstEvent || row.first_event < existing.firstEvent) {
        existing.firstEvent = row.first_event;
      }
      if (!existing.lastEvent || row.last_event > existing.lastEvent) {
        existing.lastEvent = row.last_event;
      }

      switch (row.event_type) {
        case 'sent':
          existing.sent += count;
          break;
        case 'delivered':
          existing.delivered += count;
          break;
        case 'bounced':
          existing.bounced += count;
          break;
        case 'opened':
          existing.opened += count;
          break;
        case 'clicked':
          existing.clicked += count;
          break;
        case 'unsubscribed':
        case 'list_unsubscribe':
          existing.unsubscribed += count;
          break;
        case 'complained':
          existing.complained += count;
          break;
      }

      byCampaign.set(campaignId, existing);
    }

    let campaigns = Array.from(byCampaign.entries()).map(([campaignId, stats]) => ({
      campaignId,
      ...stats,
      openRate: stats.delivered > 0 ? (stats.opened / stats.delivered) * 100 : 0,
      clickRate: stats.opened > 0 ? (stats.clicked / stats.opened) * 100 : 0,
    }));

    // Apply limit if specified
    if (options.limit && campaigns.length > options.limit) {
      campaigns = campaigns.slice(0, options.limit);
    }

    return Result.ok(campaigns);
  }

  /**
   * Get bounce breakdown statistics
   */
  async getBounceBreakdown(
    tenantId: string,
    options: { startDate?: Date; endDate?: Date; since?: Date; until?: Date; domainId?: string } = {}
  ): Promise<Result<{
    bounceType: 'hard' | 'soft';
    bounceSubtype: string;
    bounceCode: string;
    count: number;
    percentage: number;
  }[], Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['tenant_id = $1', "event_type = 'bounced'"];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      values.push(endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      bounce_type: 'hard' | 'soft';
      bounce_code: string;
      bounce_reason: string | null;
      count: string;
    }>(
      `SELECT 
        COALESCE(bounce_type, 'soft') as bounce_type,
        COALESCE(bounce_code, 'unknown') as bounce_code,
        COALESCE(bounce_reason, 'unknown') as bounce_reason,
        COUNT(*) as count
       FROM events
       ${whereClause}
       GROUP BY bounce_type, bounce_code, bounce_reason
       ORDER BY count DESC`,
      values
    );

    if (!result.ok) return result;

    const total = result.value.rows.reduce((sum, row) => sum + parseInt(row.count, 10), 0);

    return Result.ok(
      result.value.rows.map((row) => ({
        bounceType: row.bounce_type,
        bounceSubtype: row.bounce_reason ?? 'unknown',
        bounceCode: row.bounce_code,
        count: parseInt(row.count, 10),
        percentage: total > 0 ? (parseInt(row.count, 10) / total) * 100 : 0,
      }))
    );
  }
}
