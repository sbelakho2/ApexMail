/**
 * Cost Circuit Service
 * Real-time margin protection and cost monitoring
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import { COST_CHECK_INTERVAL_MINUTES, BYTES_PER_GIB } from '../lib/constants.js';

const logger = createLogger();

export interface TenantCosts {
  tenantId: string;
  period: { start: Date; end: Date };
  costs: {
    storage: number;        // In cents
    bandwidth: number;      // In cents
    compute: number;        // In cents
    dedicatedIp: number;    // In cents
    total: number;
  };
  revenue: number;          // In cents
  margin: number;           // Percentage
  marginDollars: number;    // In cents
}

export interface CostAlert {
  id: string;
  tenantId: string;
  alertType: 'low_margin' | 'negative_margin' | 'cost_spike';
  threshold: number;
  actual: number;
  costs: TenantCosts['costs'];
  revenue: number;
  triggeredAt: Date;
  resolvedAt: Date | null;
  actions: string[];
}

export interface CostCircuitConfig {
  marginWarningThreshold: number;   // Alert when margin below this %
  marginCriticalThreshold: number;  // Throttle when margin below this %
  costSpikeThreshold: number;       // Alert on day-over-day cost increase %
  checkIntervalMinutes: number;
}

interface CostRates {
  storagePerGbMonth: number;
  bandwidthPerGb: number;
  computePerHour: number;
  dedicatedIpPerMonth: number;
}

const DEFAULT_CONFIG: CostCircuitConfig = {
  marginWarningThreshold: 20,  // 20% margin
  marginCriticalThreshold: 10, // 10% margin
  costSpikeThreshold: 50,      // 50% increase
  checkIntervalMinutes: COST_CHECK_INTERVAL_MINUTES,
};

// Default cost rates (in cents per unit)
const DEFAULT_COST_RATES: CostRates = {
  storagePerGbMonth: 2.3,      // $0.023/GB/month
  bandwidthPerGb: 9,           // $0.09/GB
  computePerHour: 0.5,         // $0.005/hour per email processed
  dedicatedIpPerMonth: 2495,   // $24.95/IP/month (AWS SES dedicated IP)
};

const parseRate = (value: string | undefined, fallback: number): number => {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
};

/**
 * Cost circuit breaker for margin protection
 */
export class CostCircuitService {
  private readonly config: CostCircuitConfig;
  private readonly costRates: CostRates;

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    config?: Partial<CostCircuitConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.costRates = {
      storagePerGbMonth: parseRate(process.env['BILLING_COST_RATE_STORAGE_PER_GB_MONTH_CENTS'], DEFAULT_COST_RATES.storagePerGbMonth),
      bandwidthPerGb: parseRate(process.env['BILLING_COST_RATE_BANDWIDTH_PER_GB_CENTS'], DEFAULT_COST_RATES.bandwidthPerGb),
      computePerHour: parseRate(process.env['BILLING_COST_RATE_COMPUTE_PER_EMAIL_CENTS'], DEFAULT_COST_RATES.computePerHour),
      dedicatedIpPerMonth: parseRate(process.env['BILLING_COST_RATE_DEDICATED_IP_PER_MONTH_CENTS'], DEFAULT_COST_RATES.dedicatedIpPerMonth),
    };
  }

  /**
   * Calculate costs for a tenant
   */
  async calculateCosts(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<TenantCosts, Error>> {
    const [
      storageResult,
      bandwidthResult,
      emailsResult,
      ipResult,
      revenueResult,
    ] = await Promise.all([
      this.db.query<{ total_bytes: string }>(
        `SELECT COALESCE(SUM(size_bytes), 0)::text as total_bytes
         FROM message_attachments ma
         JOIN messages m ON ma.message_id = m.id
         WHERE m.tenant_id = $1
           AND m.created_at >= $2
           AND m.created_at < $3`,
        [tenantId, periodStart, periodEnd]
      ),
      this.db.query<{ total_bytes: string }>(
        `SELECT COALESCE(SUM(size_bytes), 0)::text as total_bytes
         FROM messages
         WHERE tenant_id = $1
           AND created_at >= $2
           AND created_at < $3
           AND status IN ('delivered', 'sent')`,
        [tenantId, periodStart, periodEnd]
      ),
      this.db.query<{ count: string }>(
        `SELECT COUNT(*)::text as count
         FROM messages
         WHERE tenant_id = $1
           AND created_at >= $2
           AND created_at < $3`,
        [tenantId, periodStart, periodEnd]
      ),
      this.db.query<{ count: string }>(
        `SELECT COUNT(*)::text as count
         FROM dedicated_ips
         WHERE tenant_id = $1
           AND status IN ('active', 'warming')
           AND created_at <= $2`,
        [tenantId, periodEnd]
      ),
      this.db.query<{ total: string }>(
        `SELECT COALESCE(SUM(total), 0)::text as total
         FROM invoices
         WHERE tenant_id = $1
           AND period_start >= $2
           AND period_end <= $3
           AND status = 'paid'`,
        [tenantId, periodStart, periodEnd]
      ),
    ]);

    const storageGb = storageResult.ok
      ? parseInt(storageResult.value.rows[0]?.total_bytes ?? '0', 10) / BYTES_PER_GIB
      : 0;
    const storageCost = Math.round(storageGb * this.costRates.storagePerGbMonth);

    const bandwidthGb = bandwidthResult.ok
      ? parseInt(bandwidthResult.value.rows[0]?.total_bytes ?? '0', 10) / BYTES_PER_GIB
      : 0;
    const bandwidthCost = Math.round(bandwidthGb * this.costRates.bandwidthPerGb);

    const emailCount = emailsResult.ok
      ? parseInt(emailsResult.value.rows[0]?.count ?? '0', 10)
      : 0;
    const computeCost = Math.round(emailCount * this.costRates.computePerHour / 100);

    const ipCount = ipResult.ok
      ? parseInt(ipResult.value.rows[0]?.count ?? '0', 10)
      : 0;
    const dedicatedIpCost = ipCount * this.costRates.dedicatedIpPerMonth;

    const totalCost = storageCost + bandwidthCost + computeCost + dedicatedIpCost;

    const revenue = revenueResult.ok
      ? parseInt(revenueResult.value.rows[0]?.total ?? '0', 10)
      : 0;

    const marginDollars = revenue - totalCost;
    const margin = revenue > 0 ? (marginDollars / revenue) * 100 : 0;

    return Result.ok({
      tenantId,
      period: { start: periodStart, end: periodEnd },
      costs: {
        storage: storageCost,
        bandwidth: bandwidthCost,
        compute: computeCost,
        dedicatedIp: dedicatedIpCost,
        total: totalCost,
      },
      revenue,
      margin: Math.round(margin * 100) / 100,
      marginDollars,
    });
  }

  /**
   * Check margin and trigger alerts/throttling
   */
  async checkMargin(tenantId: string): Promise<Result<{
    status: 'healthy' | 'warning' | 'critical';
    margin: number;
    actions: string[];
  }, Error>> {
    const now = new Date();
    // SECURITY: Use UTC for billing calculations to avoid timezone-related inconsistencies
    const periodStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));

    const costsResult = await this.calculateCosts(tenantId, periodStart, now);
    if (!costsResult.ok) return Result.err(costsResult.error);

    const { margin, costs, revenue } = costsResult.value;
    const actions: string[] = [];

    let status: 'healthy' | 'warning' | 'critical' = 'healthy';

    if (margin < this.config.marginCriticalThreshold) {
      status = 'critical';

      // Create alert
      await this.createAlert(tenantId, {
        alertType: margin < 0 ? 'negative_margin' : 'low_margin',
        threshold: this.config.marginCriticalThreshold,
        actual: margin,
        costs,
        revenue,
      });

      // Apply throttling
      await this.applyThrottling(tenantId);
      actions.push('Throttling applied: reduced sending rate');

      logger.warn('Critical margin - throttling applied', { tenantId, margin, costs, revenue });

    } else if (margin < this.config.marginWarningThreshold) {
      status = 'warning';

      await this.createAlert(tenantId, {
        alertType: 'low_margin',
        threshold: this.config.marginWarningThreshold,
        actual: margin,
        costs,
        revenue,
      });

      actions.push('Warning notification sent');

      logger.info('Low margin warning', { tenantId, margin });
    }

    // Cache status
    await this.redis.setex(
      `cost:status:${tenantId}`,
      3600,
      JSON.stringify({ status, margin, checkedAt: now })
    );

    return Result.ok({ status, margin, actions });
  }

  /**
   * Check for cost spikes (daily comparison)
   */
  async checkCostSpike(tenantId: string): Promise<Result<boolean, Error>> {
    const now = new Date();
    // SECURITY: Use UTC for billing calculations to avoid timezone/DST issues
    const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const yesterdayStart = new Date(todayStart.getTime() - 24 * 60 * 60 * 1000);

    const todayCosts = await this.calculateCosts(tenantId, todayStart, now);
    const yesterdayCosts = await this.calculateCosts(
      tenantId,
      yesterdayStart,
      todayStart
    );

    if (!todayCosts.ok || !yesterdayCosts.ok) {
      return Result.ok(false);
    }

    const todayTotal = todayCosts.value.costs.total;
    const yesterdayTotal = yesterdayCosts.value.costs.total;

    if (yesterdayTotal === 0) {
      return Result.ok(false);
    }

    const increasePercent = ((todayTotal - yesterdayTotal) / yesterdayTotal) * 100;

    if (increasePercent > this.config.costSpikeThreshold) {
      await this.createAlert(tenantId, {
        alertType: 'cost_spike',
        threshold: this.config.costSpikeThreshold,
        actual: increasePercent,
        costs: todayCosts.value.costs,
        revenue: todayCosts.value.revenue,
      });

      logger.warn('Cost spike detected', {
        tenantId,
        todayTotal,
        yesterdayTotal,
        increasePercent,
      });

      return Result.ok(true);
    }

    return Result.ok(false);
  }

  /**
   * Get current circuit status
   */
  async getCircuitStatus(tenantId: string): Promise<Result<{
    status: 'open' | 'closed' | 'half_open';
    throttled: boolean;
    margin: number | null;
    lastChecked: Date | null;
  }, Error>> {
    const cached = await this.redis.get(`cost:status:${tenantId}`);
    const throttled = await this.redis.exists(`cost:throttle:${tenantId}`);

    if (!cached) {
      return Result.ok({
        status: 'closed',
        throttled: throttled === 1,
        margin: null,
        lastChecked: null,
      });
    }

    try {
      const data = JSON.parse(cached);
      return Result.ok({
        status: data.status === 'critical' ? 'open' : 'closed',
        throttled: throttled === 1,
        margin: data.margin,
        lastChecked: new Date(data.checkedAt),
      });
    } catch (error) {
      logger.warn('Invalid cached cost status, purging', { tenantId, error: String(error) });
      await this.redis.del(`cost:status:${tenantId}`);
      return Result.ok({
        status: 'closed',
        throttled: throttled === 1,
        margin: null,
        lastChecked: null,
      });
    }
  }

  /**
   * Get cost report for tenant
   */
  async getCostReport(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<{
    costs: TenantCosts;
    breakdown: Array<{
      category: string;
      amount: number;
      percentage: number;
    }>;
    trend: Array<{
      date: Date;
      cost: number;
    }>;
  }, Error>> {
    const costsResult = await this.calculateCosts(tenantId, periodStart, periodEnd);
    if (!costsResult.ok) return Result.err(costsResult.error);

    const costs = costsResult.value;
    const total = costs.costs.total || 1;

    const breakdown = [
      { category: 'Storage', amount: costs.costs.storage, percentage: (costs.costs.storage / total) * 100 },
      { category: 'Bandwidth', amount: costs.costs.bandwidth, percentage: (costs.costs.bandwidth / total) * 100 },
      { category: 'Compute', amount: costs.costs.compute, percentage: (costs.costs.compute / total) * 100 },
      { category: 'Dedicated IPs', amount: costs.costs.dedicatedIp, percentage: (costs.costs.dedicatedIp / total) * 100 },
    ];

    // Get daily trend
    const computeRatePerMessage = this.costRates.computePerHour / 100;
    const trendResult = await this.db.query<{
      date: Date;
      cost: number;
    }>(
      `SELECT DATE(created_at) as date,
              COUNT(*) * $4 as cost
       FROM messages
       WHERE tenant_id = $1
         AND created_at >= $2
         AND created_at < $3
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [tenantId, periodStart, periodEnd, computeRatePerMessage]
    );

    const trend = trendResult.ok ? trendResult.value.rows : [];

    return Result.ok({ costs, breakdown, trend });
  }

  /**
   * Run margin check for all tenants (scheduled job)
   * Processes in batches to prevent memory exhaustion
   */
  async runMarginChecks(): Promise<Result<{
    checked: number;
    warnings: number;
    critical: number;
  }, Error>> {
    const BATCH_SIZE = 100;
    let offset = 0;
    let totalChecked = 0;
    let warnings = 0;
    let critical = 0;
    let hasMore = true;

    while (hasMore) {
      const tenantsResult = await this.db.query<{ id: string }>(
        `SELECT id FROM tenants WHERE status = 'active' ORDER BY id LIMIT $1 OFFSET $2`,
        [BATCH_SIZE, offset]
      );

      if (!tenantsResult.ok) return Result.err(tenantsResult.error);
      
      const rows = tenantsResult.value.rows;
      if (rows.length === 0) {
        hasMore = false;
        continue;
      }

      const results = await Promise.all(rows.map((row) => this.checkMargin(row.id)));
      for (const result of results) {
        if (result.ok) {
          if (result.value.status === 'warning') warnings += 1;
          if (result.value.status === 'critical') critical += 1;
        }
        totalChecked += 1;
      }

      if (rows.length < BATCH_SIZE) {
        hasMore = false;
      } else {
        offset += BATCH_SIZE;
      }
    }

    return Result.ok({
      checked: totalChecked,
      warnings,
      critical,
    });
  }

  private async createAlert(
    tenantId: string,
    params: {
      alertType: CostAlert['alertType'];
      threshold: number;
      actual: number;
      costs: TenantCosts['costs'];
      revenue: number;
    }
  ): Promise<void> {
    // Use atomic CTE to: check existing, insert alert if none exists, queue notification
    await this.db.query(
      `WITH existing_alert AS (
        SELECT id FROM cost_alerts
        WHERE tenant_id = $1 
          AND alert_type = $2
          AND resolved_at IS NULL
        LIMIT 1
      ),
      insert_alert AS (
        INSERT INTO cost_alerts (
          id, tenant_id, alert_type, threshold, actual,
          costs, revenue, triggered_at, created_at
        )
        SELECT 
          gen_random_uuid(), $1, $2, $3, $4, $5, $6, NOW(), NOW()
        WHERE NOT EXISTS (SELECT 1 FROM existing_alert)
        RETURNING id
      ),
      queue_notification AS (
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        SELECT gen_random_uuid(), $1, 'cost_alert', $7, 'pending', NOW()
        WHERE EXISTS (SELECT 1 FROM insert_alert)
        RETURNING id
      )
      SELECT EXISTS (SELECT 1 FROM insert_alert) as created`,
      [
        tenantId,
        params.alertType,
        params.threshold,
        params.actual,
        JSON.stringify(params.costs),
        params.revenue,
        JSON.stringify(params),
      ]
    );
  }

  private async applyThrottling(tenantId: string): Promise<void> {
    try {
      // Set throttle flag in Redis (24 hour TTL)
      await this.redis.setex(
        `cost:throttle:${tenantId}`,
        24 * 60 * 60,
        JSON.stringify({ appliedAt: new Date(), reason: 'low_margin' })
      );

      // Reduce rate limit to 50% of normal
      const currentLimit = await this.redis.get(`rate:limit:${tenantId}`);
      const newLimit = currentLimit ? Math.floor(parseInt(currentLimit, 10) / 2) : 50;
      await this.redis.setex(`rate:limit:${tenantId}:throttled`, 24 * 60 * 60, newLimit.toString());
    } catch (error) {
      // Log throttling failure but don't throw - degraded operation is acceptable
      // Throttling is a best-effort cost-protection measure; failure should not
      // block billing processing for the tenant.
      logger.error('Failed to apply cost-circuit throttling', {
        tenantId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
}
