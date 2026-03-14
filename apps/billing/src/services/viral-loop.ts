/**
 * Viral Loop Service
 * "Powered by ApexMail" footer injection and attribution tracking
 */

import type { Redis } from 'ioredis';
import { createHash } from 'node:crypto';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import { TTL_30_DAYS, TTL_35_DAYS } from '../lib/constants.js';

const logger = createLogger();
const PENDING_COUNTER_QUEUE_KEY = 'viral:pending:counters';
const PROCESSING_COUNTER_QUEUE_KEY = 'viral:processing:counters';
const DEAD_LETTER_COUNTER_QUEUE_KEY = 'viral:dead-letter:counters';
const MAX_PENDING_COUNTER_RETRIES = 10;

interface PendingCounterEvent {
  tenantId: string;
  metric: 'impressions' | 'clicks' | 'conversions';
  retries: number;
  queuedAt: string;
}

export interface Attribution {
  id: string;
  sourceTenantId: string;
  clickedAt: Date;
  convertedAt: Date | null;
  newTenantId: string | null;
  utmSource: string;
  utmMedium: string;
  utmCampaign: string;
  ipAddress: string;
  userAgent: string;
}

export interface ViralStats {
  tenantId: string;
  period: { start: Date; end: Date };
  footerImpressions: number;
  footerClicks: number;
  signups: number;
  conversions: number;
  clickThroughRate: number;
  conversionRate: number;
}

/**
 * Viral loop tracking and attribution
 */
export class ViralLoopService {
  private readonly baseUrl: string;
  private readonly telemetryHashSalt: string;

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    baseUrl?: string,
    telemetryHashSalt?: string
  ) {
    this.baseUrl = baseUrl ?? 'https://apexmail.ee';
    this.telemetryHashSalt = telemetryHashSalt ?? 'apexmail-telemetry';
  }

  private anonymizeIpAddress(ipAddress: string): string {
    if (ipAddress.includes('.')) {
      const octets = ipAddress.split('.');
      if (octets.length === 4) {
        return `${octets[0]}.${octets[1]}.${octets[2]}.0`;
      }
      return ipAddress;
    }

    if (ipAddress.includes(':')) {
      const hextets = ipAddress.split(':').slice(0, 4).join(':');
      return `${hextets}::`;
    }

    return ipAddress;
  }

  private hashUserAgent(userAgent: string): string {
    return createHash('sha256')
      .update(`${this.telemetryHashSalt}:${userAgent}`)
      .digest('hex');
  }

  /**
   * Generate "Powered by" footer HTML for Free tier
   */
  generatePoweredByFooter(tenantId: string, messageId: string): string {
    const trackingUrl = this.buildTrackingUrl(tenantId, messageId);
    
    return `
<!-- ApexMail Powered By Footer -->
<table role="presentation" style="width:100%;margin-top:32px;border-top:1px solid #e5e7eb;padding-top:16px;">
  <tr>
    <td style="text-align:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:12px;color:#6b7280;">
      <a href="${trackingUrl}" 
         target="_blank" 
         rel="noopener noreferrer"
         style="color:#6b7280;text-decoration:none;">
        <span style="display:inline-flex;align-items:center;gap:4px;">
          ✉️ Powered by <strong style="color:#1f2937;">ApexMail</strong>
        </span>
      </a>
    </td>
  </tr>
</table>
<!-- End ApexMail Powered By Footer -->`;
  }

  /**
   * Build tracking URL with UTM parameters
   */
  buildTrackingUrl(tenantId: string, messageId: string): string {
    const params = new URLSearchParams({
      utm_source: 'email_footer',
      utm_medium: 'email',
      utm_campaign: 'powered_by',
      utm_content: tenantId,
      ref: messageId,
    });

    return `${this.baseUrl}/signup?${params.toString()}`;
  }

  /**
   * Record footer click
   */
  async recordClick(
    sourceTenantId: string,
    messageRef: string,
    ipAddress: string,
    userAgent: string
  ): Promise<Result<{ attributionId: string; cookieValue: string }, Error>> {
    const pseudonymizedIp = this.anonymizeIpAddress(ipAddress);
    const pseudonymizedUserAgent = this.hashUserAgent(userAgent);

    const result = await this.db.query<{ id: string }>(
      `INSERT INTO viral_attributions (
        id, source_tenant_id, message_ref, clicked_at,
        utm_source, utm_medium, utm_campaign,
        ip_address, user_agent, created_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, NOW(),
        'email_footer', 'email', 'powered_by',
        $3, $4, NOW()
      )
      RETURNING id`,
      [sourceTenantId, messageRef, pseudonymizedIp, pseudonymizedUserAgent]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('INSERT RETURNING produced no rows'));
    }
    const attributionId = row.id;

    // Cache attribution for 30 days
    const cookieValue = `atr_${attributionId}`;
    await this.redis.setex(
      `viral:attr:${attributionId}`,
      TTL_30_DAYS,
      JSON.stringify({ sourceTenantId, messageRef, clickedAt: new Date() })
    );

    await this.incrementCounterReliably(sourceTenantId, 'clicks');

    logger.info('Footer click recorded', { sourceTenantId, attributionId });

    return Result.ok({ attributionId, cookieValue });
  }

  /**
   * Record conversion (signup from attribution)
   * CRITICAL: Uses atomic CTE to ensure consistency
   */
  async recordConversion(
    attributionId: string,
    newTenantId: string
  ): Promise<Result<void, Error>> {
    // Use atomic CTE to update attribution and return source tenant
    const result = await this.db.query<{ source_tenant_id: string }>(
      `WITH update_attribution AS (
        UPDATE viral_attributions
        SET converted_at = NOW(), new_tenant_id = $1
        WHERE id = $2
        RETURNING source_tenant_id
      )
      SELECT source_tenant_id FROM update_attribution`,
      [newTenantId, attributionId]
    );

    if (!result.ok) return Result.err(result.error);
    
    if (!result.value.rows[0]) {
      return Result.err(new Error('Attribution not found'));
    }

    await this.incrementCounterReliably(result.value.rows[0].source_tenant_id, 'conversions');

    logger.info('Viral conversion recorded', { attributionId, newTenantId });

    return Result.ok(undefined);
  }

  /**
   * Record footer impression (for emails sent)
   */
  async recordImpression(tenantId: string): Promise<void> {
    await this.incrementCounterReliably(tenantId, 'impressions');
  }

  async flushPendingCounters(limit: number = 100): Promise<number> {
    let flushed = 0;

    for (let index = 0; index < limit; index += 1) {
      const payload = await this.redis.rpoplpush(PENDING_COUNTER_QUEUE_KEY, PROCESSING_COUNTER_QUEUE_KEY);
      if (!payload) {
        break;
      }

      let event: PendingCounterEvent | null = null;
      try {
        event = JSON.parse(payload) as PendingCounterEvent;
      } catch (error) {
        logger.error('Failed to parse queued viral counter event', { payload, error: String(error) });
        await this.redis.lrem(PROCESSING_COUNTER_QUEUE_KEY, 1, payload);
        continue;
      }

      try {
        await this.incrementCounter(event.tenantId, event.metric);
        await this.redis.lrem(PROCESSING_COUNTER_QUEUE_KEY, 1, payload);
        flushed += 1;
      } catch (error) {
        await this.redis.lrem(PROCESSING_COUNTER_QUEUE_KEY, 1, payload);

        const nextEvent: PendingCounterEvent = {
          ...event,
          retries: event.retries + 1,
        };

        if (nextEvent.retries >= MAX_PENDING_COUNTER_RETRIES) {
          await this.redis.lpush(DEAD_LETTER_COUNTER_QUEUE_KEY, JSON.stringify(nextEvent));
          await this.redis.expire(DEAD_LETTER_COUNTER_QUEUE_KEY, TTL_35_DAYS);
          logger.error('Dropped viral counter event after repeated failures', nextEvent);
          continue;
        }

        await this.redis.lpush(PENDING_COUNTER_QUEUE_KEY, JSON.stringify(nextEvent));
        await this.redis.expire(PENDING_COUNTER_QUEUE_KEY, TTL_35_DAYS);
        logger.warn('Failed to replay queued viral counter event', {
          tenantId: event.tenantId,
          metric: event.metric,
          retries: nextEvent.retries,
          error: String(error),
        });
        break;
      }
    }

    return flushed;
  }

  /**
   * Get viral stats for tenant
   */
  async getStats(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<ViralStats, Error>> {
    // Get impressions from metering
    const impressionsResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*)::text as count FROM metering_events
       WHERE tenant_id = $1
         AND event_type = 'emails_sent'
         AND timestamp >= $2
         AND timestamp < $3`,
      [tenantId, periodStart, periodEnd]
    );

    const impressions = impressionsResult.ok 
      ? parseInt(impressionsResult.value.rows[0]?.count ?? '0', 10)
      : 0;

    // Get clicks and conversions
    const statsResult = await this.db.query<{
      clicks: string;
      conversions: string;
    }>(
      `SELECT 
         COUNT(*)::text as clicks,
         COUNT(*) FILTER (WHERE converted_at IS NOT NULL)::text as conversions
       FROM viral_attributions
       WHERE source_tenant_id = $1
         AND clicked_at >= $2
         AND clicked_at < $3`,
      [tenantId, periodStart, periodEnd]
    );

    const clicks = statsResult.ok
      ? parseInt(statsResult.value.rows[0]?.clicks ?? '0', 10)
      : 0;

    const conversions = statsResult.ok
      ? parseInt(statsResult.value.rows[0]?.conversions ?? '0', 10)
      : 0;

    // Get signups (unique new tenants from this source)
    const signupsResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(DISTINCT new_tenant_id)::text as count
       FROM viral_attributions
       WHERE source_tenant_id = $1
         AND converted_at >= $2
         AND converted_at < $3`,
      [tenantId, periodStart, periodEnd]
    );

    const signups = signupsResult.ok
      ? parseInt(signupsResult.value.rows[0]?.count ?? '0', 10)
      : 0;

    return Result.ok({
      tenantId,
      period: { start: periodStart, end: periodEnd },
      footerImpressions: impressions,
      footerClicks: clicks,
      signups,
      conversions,
      clickThroughRate: impressions > 0 ? (clicks / impressions) * 100 : 0,
      conversionRate: clicks > 0 ? (conversions / clicks) * 100 : 0,
    });
  }

  /**
   * Check if tenant should have footer (Free tier only)
   */
  async shouldShowFooter(tenantId: string): Promise<Result<boolean, Error>> {
    const result = await this.db.query<{
      features: string;
    }>(
      `SELECT p.features FROM tenants t
       JOIN plans p ON t.plan = p.name
       WHERE t.id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(true); // Default to showing footer

    // Safe JSON parsing for features
    let features: Record<string, unknown> = {};
    try {
      features = JSON.parse(row.features || '{}') as Record<string, unknown>;
    } catch (error) {
      logger.warn('Failed to parse plan features for tenant', { tenantId, error });
      return Result.ok(true); // Default to showing footer on parse error
    }
    
    return Result.ok(features.poweredByFooter === true);
  }

  /**
   * Get leaderboard of top referrers
   */
  async getLeaderboard(
    periodStart: Date,
    periodEnd: Date,
    limit: number = 10
  ): Promise<Result<Array<{
    tenantId: string;
    tenantName: string;
    conversions: number;
    clicks: number;
  }>, Error>> {
    const result = await this.db.query<{
      source_tenant_id: string;
      tenant_name: string;
      conversions: string;
      clicks: string;
    }>(
      `SELECT 
         va.source_tenant_id,
         t.name as tenant_name,
         COUNT(*) FILTER (WHERE va.converted_at IS NOT NULL)::text as conversions,
         COUNT(*)::text as clicks
       FROM viral_attributions va
       JOIN tenants t ON va.source_tenant_id = t.id
       WHERE va.clicked_at >= $1 AND va.clicked_at < $2
       GROUP BY va.source_tenant_id, t.name
       ORDER BY conversions DESC, clicks DESC
       LIMIT $3`,
      [periodStart, periodEnd, limit]
    );

    if (!result.ok) return Result.err(result.error);

    return Result.ok(result.value.rows.map(row => ({
      tenantId: row.source_tenant_id,
      tenantName: row.tenant_name,
      conversions: parseInt(row.conversions, 10),
      clicks: parseInt(row.clicks, 10),
    })));
  }

  private async incrementCounter(
    tenantId: string,
    metric: 'impressions' | 'clicks' | 'conversions'
  ): Promise<void> {
    const periodKey = this.getPeriodKey(new Date());
    const key = `viral:${metric}:${tenantId}:${periodKey}`;
    await this.redis.incr(key);
    await this.redis.expire(key, TTL_35_DAYS); // 35 days
  }

  private async incrementCounterReliably(
    tenantId: string,
    metric: 'impressions' | 'clicks' | 'conversions'
  ): Promise<void> {
    try {
      await this.incrementCounter(tenantId, metric);
      await this.flushPendingCounters(10);
    } catch (error) {
      const event: PendingCounterEvent = {
        tenantId,
        metric,
        retries: 0,
        queuedAt: new Date().toISOString(),
      };

      try {
        await this.redis.lpush(PENDING_COUNTER_QUEUE_KEY, JSON.stringify(event));
        await this.redis.ltrim(PENDING_COUNTER_QUEUE_KEY, 0, 4_999);
        await this.redis.expire(PENDING_COUNTER_QUEUE_KEY, TTL_35_DAYS);
        logger.error('Queued viral counter event after Redis failure', { tenantId, metric, error: String(error) });
      } catch (queueError) {
        logger.error('Failed to queue viral counter event', {
          tenantId,
          metric,
          error: String(error),
          queueError: String(queueError),
        });
      }
    }
  }

  private getPeriodKey(date: Date): string {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
  }
}
