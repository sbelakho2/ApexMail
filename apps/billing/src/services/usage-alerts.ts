/**
 * Usage Alerts Service
 * Sends notifications at configurable usage thresholds
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import { MeteringService } from './metering.js';

const logger = createLogger();

export interface UsageThreshold {
  id: string;
  tenantId: string;
  metricType: 'emails' | 'api_calls' | 'storage';
  thresholdPercent: number;
  notificationChannel: 'email' | 'webhook' | 'both';
  isEnabled: boolean;
  lastTriggeredAt: Date | null;
}

export interface AlertConfig {
  defaultThresholds: number[]; // Default: [50, 80, 100]
  cooldownMinutes: number; // Don't re-alert within this window
}

/**
 * Usage alerts service - monitors and notifies on threshold breaches
 */
export class UsageAlertsService {
  private readonly config: AlertConfig;

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    private readonly metering: MeteringService,
    config?: Partial<AlertConfig>
  ) {
    this.config = {
      defaultThresholds: config?.defaultThresholds ?? [50, 80, 100],
      cooldownMinutes: config?.cooldownMinutes ?? 60,
    };
  }

  /**
   * Configure thresholds for a tenant
   */
  async configureThresholds(
    tenantId: string,
    thresholds: Array<{
      metricType: UsageThreshold['metricType'];
      thresholdPercent: number;
      notificationChannel: UsageThreshold['notificationChannel'];
    }>
  ): Promise<Result<UsageThreshold[], Error>> {
    const results: UsageThreshold[] = [];

    for (const threshold of thresholds) {
      const result = await this.db.query<{
        id: string;
        tenant_id: string;
        metric_type: UsageThreshold['metricType'];
        threshold_percent: number;
        notification_channel: UsageThreshold['notificationChannel'];
        enabled: boolean;
        last_triggered_at: Date | null;
      }>(
        `INSERT INTO usage_alert_configs (id, tenant_id, metric_type, threshold_percent, notification_channel, enabled)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, true)
         ON CONFLICT (tenant_id, metric_type, threshold_percent)
         DO UPDATE SET notification_channel = $4, enabled = true, updated_at = NOW()
         RETURNING *`,
        [tenantId, threshold.metricType, threshold.thresholdPercent, threshold.notificationChannel]
      );

      if (!result.ok) return Result.err(result.error);

      const row = result.value.rows[0];
      if (row) {
        results.push({
          id: row.id,
          tenantId: row.tenant_id,
          metricType: row.metric_type,
          thresholdPercent: row.threshold_percent,
          notificationChannel: row.notification_channel,
          isEnabled: row.enabled,
          lastTriggeredAt: row.last_triggered_at,
        });
      }
    }

    return Result.ok(results);
  }

  /**
   * Check usage and trigger alerts if thresholds exceeded
   */
  async checkAndAlert(tenantId: string): Promise<Result<{
    alertsTriggered: number;
    currentUsage: { emails: number; apiCalls: number };
  }, Error>> {
    // Get current billing period
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    // Get current usage
    const usageResult = await this.metering.getUsage(tenantId, periodStart, periodEnd);
    if (!usageResult.ok) return Result.err(usageResult.error);

    const usage = usageResult.value;
    const { emailsSent, emailsLimit, apiCalls, apiCallsLimit } = usage.billingCycleUsage;

    // Get configured thresholds
    const thresholdsResult = await this.db.query<{
      id: string;
      tenant_id: string;
      metric_type: UsageThreshold['metricType'];
      threshold_percent: number;
      notification_channel: UsageThreshold['notificationChannel'];
      last_triggered_at: Date | null;
    }>(
      `SELECT id, tenant_id, metric_type, threshold_percent,
              notification_channel, last_triggered_at
       FROM usage_alert_configs
       WHERE tenant_id = $1 AND enabled = true
       ORDER BY threshold_percent ASC`,
      [tenantId]
    );

    if (!thresholdsResult.ok) return Result.err(thresholdsResult.error);

    let alertsTriggered = 0;

    for (const threshold of thresholdsResult.value.rows) {
      const cooldownKey = `alert:cooldown:${tenantId}:${threshold.metric_type}:${threshold.threshold_percent}`;
      const inCooldown = await this.redis.exists(cooldownKey);

      if (inCooldown) continue;

      let currentPercent = 0;
      let currentValue = 0;
      let limitValue = 0;

      switch (threshold.metric_type) {
        case 'emails':
          // Guard against division by zero
          currentPercent = emailsLimit > 0 ? (emailsSent / emailsLimit) * 100 : 0;
          currentValue = emailsSent;
          limitValue = emailsLimit;
          break;
        case 'api_calls':
          // Guard against division by zero
          currentPercent = apiCallsLimit > 0 ? (apiCalls / apiCallsLimit) * 100 : 0;
          currentValue = apiCalls;
          limitValue = apiCallsLimit;
          break;
        default:
          continue;
      }

      if (currentPercent >= threshold.threshold_percent) {
        // Trigger alert
        await this.sendAlert(tenantId, {
          metricType: threshold.metric_type,
          thresholdPercent: threshold.threshold_percent,
          currentPercent: Math.round(currentPercent),
          currentValue,
          limitValue,
          channel: threshold.notification_channel,
        });

        // Set cooldown
        await this.redis.setex(cooldownKey, this.config.cooldownMinutes * 60, '1');

        // Update last triggered
        await this.db.query(
          `UPDATE usage_alert_configs SET last_triggered_at = NOW() WHERE id = $1`,
          [threshold.id]
        );

        alertsTriggered++;
        logger.info('Usage alert triggered', {
          tenantId,
          metricType: threshold.metric_type,
          threshold: threshold.threshold_percent,
          current: currentPercent,
        });
      }
    }

    return Result.ok({
      alertsTriggered,
      currentUsage: { emails: emailsSent, apiCalls },
    });
  }

  /**
   * Send alert notification
   * CRITICAL: Uses atomic CTE to queue notifications together
   */
  private async sendAlert(
    tenantId: string,
    alert: {
      metricType: UsageThreshold['metricType'];
      thresholdPercent: number;
      currentPercent: number;
      currentValue: number;
      limitValue: number;
      channel: UsageThreshold['notificationChannel'];
    }
  ): Promise<void> {
    try {
      // Get tenant email
      const tenantResult = await this.db.query<{
        name: string;
        settings: string;
      }>(
        `SELECT name, settings FROM tenants WHERE id = $1`,
        [tenantId]
      );

      if (!tenantResult.ok || !tenantResult.value.rows[0]) return;

      const tenant = tenantResult.value.rows[0];
      let settings: { webhookUrl?: string } = {};
      try {
        settings = JSON.parse(tenant.settings || '{}');
      } catch {
        settings = {};
      }
      const webhookUrl = settings.webhookUrl;

      const emailPayload = JSON.stringify({
        type: 'usage_alert',
        metricType: alert.metricType,
        thresholdPercent: alert.thresholdPercent,
        currentPercent: alert.currentPercent,
        currentValue: alert.currentValue,
        limitValue: alert.limitValue,
      });

      const webhookPayload = JSON.stringify({
        event: 'usage.threshold_reached',
        data: {
          metricType: alert.metricType,
          thresholdPercent: alert.thresholdPercent,
          currentPercent: alert.currentPercent,
          currentValue: alert.currentValue,
          limitValue: alert.limitValue,
        },
        timestamp: new Date().toISOString(),
      });

      const shouldEmail = alert.channel === 'email' || alert.channel === 'both';
      const shouldWebhook = (alert.channel === 'webhook' || alert.channel === 'both') && webhookUrl;

      // Use atomic CTE to queue both notifications together
      await this.db.query(
        `WITH queue_email AS (
          INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
          SELECT gen_random_uuid(), $1, 'usage_alert', $2, 'pending', NOW()
          WHERE $4 = true
          RETURNING id
        ),
        queue_webhook AS (
          INSERT INTO webhook_deliveries (id, tenant_id, event_type, payload, status, created_at)
          SELECT gen_random_uuid(), $1, 'usage.threshold_reached', $3, 'pending', NOW()
          WHERE $5 = true
          RETURNING id
        )
      SELECT 
        EXISTS (SELECT 1 FROM queue_email) as email_queued,
        EXISTS (SELECT 1 FROM queue_webhook) as webhook_queued`,
      [tenantId, emailPayload, webhookPayload, shouldEmail, shouldWebhook]
    );
    } catch (error) {
      logger.error('Failed to send usage alert notification', {
        tenantId,
        error: error instanceof Error ? error.message : String(error),
      });
      // Don't throw - alert failures shouldn't block other processing
    }
  }

  /**
   * Run batch check for all tenants (cron job)
   * Processes in batches to prevent memory exhaustion
   */
  async checkAllTenants(): Promise<Result<{
    tenantsChecked: number;
    totalAlerts: number;
  }, Error>> {
    const BATCH_SIZE = 100;
    let offset = 0;
    let totalChecked = 0;
    let totalAlerts = 0;
    let hasMore = true;

    while (hasMore) {
      const tenantsResult = await this.db.query<{ id: string }>(
        `SELECT DISTINCT tenant_id as id FROM usage_alert_configs 
         WHERE enabled = true 
         ORDER BY tenant_id 
         LIMIT $1 OFFSET $2`,
        [BATCH_SIZE, offset]
      );

      if (!tenantsResult.ok) return Result.err(tenantsResult.error);

      const rows = tenantsResult.value.rows;
      if (rows.length === 0) {
        hasMore = false;
        continue;
      }

      for (const row of rows) {
        const result = await this.checkAndAlert(row.id);
        if (result.ok) {
          totalAlerts += result.value.alertsTriggered;
        }
        totalChecked++;
      }

      if (rows.length < BATCH_SIZE) {
        hasMore = false;
      } else {
        offset += BATCH_SIZE;
      }
    }

    return Result.ok({
      tenantsChecked: totalChecked,
      totalAlerts,
    });
  }
}
