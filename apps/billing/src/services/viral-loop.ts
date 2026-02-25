/**
 * Viral Loop Service
 * "Powered by ApexMail" footer injection and attribution tracking
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger();

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

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    baseUrl?: string
  ) {
    this.baseUrl = baseUrl ?? 'https://apexmail.ee';
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
      [sourceTenantId, messageRef, ipAddress, userAgent]
    );

    if (!result.ok) return Result.err(result.error);

    if (result.value.rows.length === 0) {
      return Result.err(new Error('INSERT RETURNING produced no rows'));
    }
    const attributionId = result.value.rows[0]!.id;

    // Cache attribution for 30 days
    const cookieValue = `atr_${attributionId}`;
    await this.redis.setex(
      `viral:attr:${attributionId}`,
      30 * 24 * 60 * 60,
      JSON.stringify({ sourceTenantId, messageRef, clickedAt: new Date() })
    );

    // Update click count
    await this.incrementCounter(sourceTenantId, 'clicks');

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

    // Update Redis counter (non-critical, can be eventually consistent)
    await this.incrementCounter(result.value.rows[0].source_tenant_id, 'conversions');

    logger.info('Viral conversion recorded', { attributionId, newTenantId });

    return Result.ok(undefined);
  }

  /**
   * Record footer impression (for emails sent)
   */
  async recordImpression(tenantId: string): Promise<void> {
    try {
      await this.incrementCounter(tenantId, 'impressions');
    } catch (error) {
      console.error(`[ViralLoop] Failed to record impression for tenant ${tenantId}:`, error);
      // Don't throw - analytics failures shouldn't block email delivery
    }
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
      try {
        features = JSON.parse(row.features || '{}');
      } catch {
        features = {};
      }
    } catch {
      console.warn(`[ViralLoop] Failed to parse plan features for tenant ${tenantId}`);
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
    await this.redis.expire(key, 35 * 24 * 60 * 60); // 35 days
  }

  private getPeriodKey(date: Date): string {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
  }
}
