/**
 * SLA Credits Service
 * Automatic credit calculation when SLOs are breached
 */

import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger('sla-credits');

export interface SloTarget {
  name: string;
  target: number;
  unit: 'percentage' | 'milliseconds';
  period: 'monthly';
}

export interface SloBreach {
  id: string;
  tenantId: string;
  sloName: string;
  target: number;
  actual: number;
  period: { start: Date; end: Date };
  creditPercentage: number;
  creditAmount: number;
  appliedAt: Date | null;
  createdAt: Date;
}

export interface SlaConfig {
  availabilityTarget: number;    // e.g., 99.9
  latencyP95Target: number;      // e.g., 200 (ms)
  creditTiers: Array<{
    breachThreshold: number;     // % below target
    creditPercentage: number;    // % of invoice to credit
  }>;
}

const DEFAULT_SLA_CONFIG: SlaConfig = {
  availabilityTarget: 99.9,
  latencyP95Target: 200,
  creditTiers: [
    { breachThreshold: 0.1, creditPercentage: 10 },  // 99.8% availability -> 10% credit
    { breachThreshold: 0.5, creditPercentage: 25 },  // 99.4% availability -> 25% credit
    { breachThreshold: 1.0, creditPercentage: 50 },  // 98.9% availability -> 50% credit
    { breachThreshold: 5.0, creditPercentage: 100 }, // <95% availability -> 100% credit
  ],
};

/**
 * SLA credit automation service
 */
export class SlaCreditsService {
  private readonly config: SlaConfig;

  constructor(
    private readonly db: DatabasePool,
    config?: Partial<SlaConfig>
  ) {
    this.config = { ...DEFAULT_SLA_CONFIG, ...config };
  }

  /**
   * Check SLO compliance and calculate credits for a period
   */
  async checkCompliance(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<{
    breaches: SloBreach[];
    totalCreditAmount: number;
  }, Error>> {
    const breaches: SloBreach[] = [];

    // Check availability SLO
    const availabilityResult = await this.calculateAvailability(tenantId, periodStart, periodEnd);
    if (availabilityResult.ok) {
      const { actual } = availabilityResult.value;
      const target = this.config.availabilityTarget;

      if (actual < target) {
        const breach = await this.createBreach(tenantId, {
          sloName: 'availability',
          target,
          actual,
          period: { start: periodStart, end: periodEnd },
        });

        if (breach.ok && breach.value) {
          breaches.push(breach.value);
        }
      }
    }

    // Check latency SLO
    const latencyResult = await this.calculateLatencyP95(tenantId, periodStart, periodEnd);
    if (latencyResult.ok) {
      const { actual } = latencyResult.value;
      const target = this.config.latencyP95Target;

      if (actual > target) {
        // For latency, being higher than target is a breach
        const breachPercentage = ((actual - target) / target) * 100;
        const breach = await this.createBreach(tenantId, {
          sloName: 'latency_p95',
          target,
          actual,
          period: { start: periodStart, end: periodEnd },
          breachPercentage,
        });

        if (breach.ok && breach.value) {
          breaches.push(breach.value);
        }
      }
    }

    const totalCreditAmount = breaches.reduce((sum, b) => sum + b.creditAmount, 0);

    return Result.ok({ breaches, totalCreditAmount });
  }

  /**
   * Create SLO breach record with credit calculation
   */
  private async createBreach(
    tenantId: string,
    params: {
      sloName: string;
      target: number;
      actual: number;
      period: { start: Date; end: Date };
      breachPercentage?: number;
    }
  ): Promise<Result<SloBreach | null, Error>> {
    // Check if tenant has SLA guarantee
    const planResult = await this.db.query<{
      features: string;
    }>(
      `SELECT p.features FROM tenants t
       JOIN plans p ON t.plan = p.name
       WHERE t.id = $1`,
      [tenantId]
    );

    if (!planResult.ok) return Result.err(planResult.error);

    const row = planResult.value.rows[0];
    if (!row) return Result.ok(null);

    const features = JSON.parse(row.features);
    if (!features.slaGuarantee) {
      return Result.ok(null); // No SLA guarantee on this plan
    }

    // Calculate breach percentage
    let breachPercentage = params.breachPercentage;
    if (breachPercentage === undefined) {
      breachPercentage = params.target - params.actual;
    }

    // Determine credit percentage from tiers
    const creditPercentage = this.getCreditPercentage(breachPercentage);
    if (creditPercentage === 0) {
      return Result.ok(null);
    }

    // Get invoice amount for the period
    const invoiceResult = await this.db.query<{ total: number }>(
      `SELECT COALESCE(SUM(total), 0) as total FROM invoices
       WHERE tenant_id = $1
         AND period_start >= $2
         AND period_end <= $3`,
      [tenantId, params.period.start, params.period.end]
    );

    const invoiceAmount = invoiceResult.ok ? invoiceResult.value.rows[0]?.total ?? 0 : 0;
    const creditAmount = Math.round((invoiceAmount * creditPercentage) / 100);

    // Check for existing breach in same period
    const existingResult = await this.db.query<{ id: string }>(
      `SELECT id FROM slo_breaches
       WHERE tenant_id = $1
         AND slo_name = $2
         AND period_start = $3`,
      [tenantId, params.sloName, params.period.start]
    );

    if (!existingResult.ok) return Result.err(existingResult.error);

    if (existingResult.value.rows.length > 0) {
      // Already recorded
      return Result.ok(null);
    }

    // Insert breach record
    const insertResult = await this.db.query<{
      id: string;
      created_at: Date;
    }>(
      `INSERT INTO slo_breaches (
        id, tenant_id, slo_name, target, actual,
        period_start, period_end, credit_percentage, credit_amount,
        created_at
      )
      VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW())
      RETURNING id, created_at`,
      [
        tenantId,
        params.sloName,
        params.target,
        params.actual,
        params.period.start,
        params.period.end,
        creditPercentage,
        creditAmount,
      ]
    );

    if (!insertResult.ok) return Result.err(insertResult.error);

    const inserted = insertResult.value.rows[0];
    if (!inserted) return Result.ok(null);

    logger.info({
      tenantId,
      sloName: params.sloName,
      target: params.target,
      actual: params.actual,
      creditPercentage,
      creditAmount,
    }, 'SLO breach recorded');

    return Result.ok({
      id: inserted.id,
      tenantId,
      sloName: params.sloName,
      target: params.target,
      actual: params.actual,
      period: params.period,
      creditPercentage,
      creditAmount,
      appliedAt: null,
      createdAt: inserted.created_at,
    });
  }

  /**
   * Apply pending credits to next invoice
   */
  async applyPendingCredits(tenantId: string): Promise<Result<{
    appliedCredits: SloBreach[];
    totalAmount: number;
  }, Error>> {
    // Get unapplied breaches
    const breachesResult = await this.db.query<{
      id: string;
      tenant_id: string;
      slo_name: string;
      target: number;
      actual: number;
      period_start: Date;
      period_end: Date;
      credit_percentage: number;
      credit_amount: number;
      created_at: Date;
    }>(
      `SELECT * FROM slo_breaches
       WHERE tenant_id = $1 AND applied_at IS NULL
       ORDER BY created_at ASC`,
      [tenantId]
    );

    if (!breachesResult.ok) return Result.err(breachesResult.error);

    const appliedCredits: SloBreach[] = [];
    let totalAmount = 0;

    for (const row of breachesResult.value.rows) {
      // Mark as applied
      await this.db.query(
        `UPDATE slo_breaches SET applied_at = NOW() WHERE id = $1`,
        [row.id]
      );

      appliedCredits.push({
        id: row.id,
        tenantId: row.tenant_id,
        sloName: row.slo_name,
        target: row.target,
        actual: row.actual,
        period: { start: row.period_start, end: row.period_end },
        creditPercentage: row.credit_percentage,
        creditAmount: row.credit_amount,
        appliedAt: new Date(),
        createdAt: row.created_at,
      });

      totalAmount += row.credit_amount;
    }

    // Create credit memo if any credits applied
    if (totalAmount > 0) {
      await this.db.query(
        `INSERT INTO credit_memos (
          id, tenant_id, amount, reason, slo_breach_ids, created_at
        )
        VALUES (gen_random_uuid(), $1, $2, 'SLO Credit', $3, NOW())`,
        [tenantId, totalAmount, appliedCredits.map(c => c.id)]
      );

      // Queue notification
      await this.db.query(
        `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
         VALUES (gen_random_uuid(), $1, 'sla_credit_applied', $2, 'pending', NOW())`,
        [tenantId, JSON.stringify({ amount: totalAmount, credits: appliedCredits })]
      );

      logger.info({ tenantId, totalAmount, creditCount: appliedCredits.length }, 'SLA credits applied');
    }

    return Result.ok({ appliedCredits, totalAmount });
  }

  /**
   * Get pending credits for tenant
   */
  async getPendingCredits(tenantId: string): Promise<Result<{
    breaches: SloBreach[];
    totalAmount: number;
  }, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      slo_name: string;
      target: number;
      actual: number;
      period_start: Date;
      period_end: Date;
      credit_percentage: number;
      credit_amount: number;
      created_at: Date;
    }>(
      `SELECT * FROM slo_breaches
       WHERE tenant_id = $1 AND applied_at IS NULL
       ORDER BY created_at DESC`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const breaches: SloBreach[] = result.value.rows.map(row => ({
      id: row.id,
      tenantId: row.tenant_id,
      sloName: row.slo_name,
      target: row.target,
      actual: row.actual,
      period: { start: row.period_start, end: row.period_end },
      creditPercentage: row.credit_percentage,
      creditAmount: row.credit_amount,
      appliedAt: null,
      createdAt: row.created_at,
    }));

    const totalAmount = breaches.reduce((sum, b) => sum + b.creditAmount, 0);

    return Result.ok({ breaches, totalAmount });
  }

  /**
   * Calculate availability for a period
   */
  private async calculateAvailability(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<{ actual: number }, Error>> {
    // Calculate from health check data
    const result = await this.db.query<{
      total_checks: string;
      successful_checks: string;
    }>(
      `SELECT 
         COUNT(*)::text as total_checks,
         COUNT(*) FILTER (WHERE status = 'healthy')::text as successful_checks
       FROM health_check_logs
       WHERE checked_at >= $1 AND checked_at < $2`,
      [periodStart, periodEnd]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    const total = parseInt(row?.total_checks ?? '0', 10);
    const successful = parseInt(row?.successful_checks ?? '0', 10);

    const actual = total > 0 ? (successful / total) * 100 : 100;

    return Result.ok({ actual: Math.round(actual * 100) / 100 });
  }

  /**
   * Calculate P95 latency for a period
   */
  private async calculateLatencyP95(
    tenantId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<{ actual: number }, Error>> {
    const result = await this.db.query<{
      p95_latency: number;
    }>(
      `SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_latency
       FROM api_request_logs
       WHERE tenant_id = $1
         AND created_at >= $2
         AND created_at < $3`,
      [tenantId, periodStart, periodEnd]
    );

    if (!result.ok) return Result.err(result.error);

    const actual = result.value.rows[0]?.p95_latency ?? 0;

    return Result.ok({ actual });
  }

  private getCreditPercentage(breachPercentage: number): number {
    for (const tier of [...this.config.creditTiers].reverse()) {
      if (breachPercentage >= tier.breachThreshold) {
        return tier.creditPercentage;
      }
    }
    return 0;
  }

  /**
   * Run monthly SLO check for all enterprise tenants
   */
  async runMonthlyCheck(): Promise<Result<{
    tenantsChecked: number;
    totalBreaches: number;
    totalCredits: number;
  }, Error>> {
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const periodEnd = new Date(now.getFullYear(), now.getMonth(), 1);

    // Get enterprise tenants with SLA guarantee
    const tenantsResult = await this.db.query<{ id: string }>(
      `SELECT t.id FROM tenants t
       JOIN plans p ON t.plan = p.name
       WHERE (p.features::jsonb->>'slaGuarantee')::boolean = true`
    );

    if (!tenantsResult.ok) return Result.err(tenantsResult.error);

    let totalBreaches = 0;
    let totalCredits = 0;

    for (const row of tenantsResult.value.rows) {
      const result = await this.checkCompliance(row.id, periodStart, periodEnd);
      if (result.ok) {
        totalBreaches += result.value.breaches.length;
        totalCredits += result.value.totalCreditAmount;
      }
    }

    return Result.ok({
      tenantsChecked: tenantsResult.value.rows.length,
      totalBreaches,
      totalCredits,
    });
  }
}
