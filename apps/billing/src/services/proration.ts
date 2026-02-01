/**
 * Proration Engine
 * Calculates pro-rated charges for plan changes
 */

import { Result } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';
import { PlansService, type Plan } from './plans.js';

export interface ProrationResult {
  creditAmount: number;        // Credit for unused time (in cents)
  chargeAmount: number;        // Charge for new plan (in cents)
  netAmount: number;           // Net charge/credit (positive = charge, negative = credit)
  currentPlanDaysRemaining: number;
  newPlanDaysInPeriod: number;
  effectiveDate: Date;
  explanation: string;
}

export interface SubscriptionPeriod {
  start: Date;
  end: Date;
  daysInPeriod: number;
  daysElapsed: number;
  daysRemaining: number;
}

/**
 * Proration calculation engine for subscription changes
 */
export class ProrationEngine {
  constructor(
    private readonly db: DatabasePool,
    private readonly plans: PlansService
  ) {}

  /**
   * Calculate proration for plan change
   */
  calculateProration(
    currentPlan: Plan,
    newPlan: Plan,
    currentPeriod: SubscriptionPeriod,
    isYearly: boolean
  ): ProrationResult {
    const currentPrice = isYearly 
      ? currentPlan.priceYearly / 12 
      : currentPlan.priceMonthly;
    const newPrice = isYearly 
      ? newPlan.priceYearly / 12 
      : newPlan.priceMonthly;

    const { daysInPeriod, daysRemaining } = currentPeriod;

    // Calculate daily rates
    const currentDailyRate = currentPrice / daysInPeriod;
    const newDailyRate = newPrice / daysInPeriod;

    // Credit for unused days on current plan
    const creditAmount = Math.round(currentDailyRate * daysRemaining);

    // Charge for remaining days on new plan
    const chargeAmount = Math.round(newDailyRate * daysRemaining);

    // Net amount (positive = customer pays, negative = customer gets credit)
    const netAmount = chargeAmount - creditAmount;

    const explanation = this.buildExplanation(
      currentPlan,
      newPlan,
      currentPrice,
      newPrice,
      daysRemaining,
      daysInPeriod,
      creditAmount,
      chargeAmount,
      netAmount
    );

    return {
      creditAmount,
      chargeAmount,
      netAmount,
      currentPlanDaysRemaining: daysRemaining,
      newPlanDaysInPeriod: daysRemaining,
      effectiveDate: new Date(),
      explanation,
    };
  }

  /**
   * Calculate subscription period details
   */
  calculatePeriod(billingCycleStart: Date, billingCycleEnd: Date): SubscriptionPeriod {
    const now = new Date();
    const start = new Date(billingCycleStart);
    const end = new Date(billingCycleEnd);

    const daysInPeriod = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    const daysElapsed = Math.ceil((now.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    const daysRemaining = Math.max(0, daysInPeriod - daysElapsed);

    return {
      start,
      end,
      daysInPeriod,
      daysElapsed,
      daysRemaining,
    };
  }

  /**
   * Preview proration for a potential plan change
   */
  async previewProration(
    tenantId: string,
    newPlanName: string
  ): Promise<Result<ProrationResult, Error>> {
    // Get tenant's current subscription
    const subResult = await this.db.query<{
      plan: string;
      billing_cycle_start: Date;
      billing_cycle_end: Date;
      billing_interval: 'monthly' | 'yearly';
    }>(
      `SELECT t.plan, s.billing_cycle_start, s.billing_cycle_end, s.billing_interval
       FROM tenants t
       LEFT JOIN subscriptions s ON t.id = s.tenant_id AND s.status = 'active'
       WHERE t.id = $1`,
      [tenantId]
    );

    if (!subResult.ok) return Result.err(subResult.error);

    const row = subResult.value.rows[0];
    if (!row) return Result.err(new Error('Tenant not found'));

    // Get current and new plans
    const currentPlanResult = await this.plans.getPlanByName(row.plan);
    if (!currentPlanResult.ok) return Result.err(currentPlanResult.error);
    if (!currentPlanResult.value) return Result.err(new Error('Current plan not found'));

    const newPlanResult = await this.plans.getPlanByName(newPlanName);
    if (!newPlanResult.ok) return Result.err(newPlanResult.error);
    if (!newPlanResult.value) return Result.err(new Error('New plan not found'));

    // Calculate period
    const period = this.calculatePeriod(row.billing_cycle_start, row.billing_cycle_end);

    // Calculate proration
    const proration = this.calculateProration(
      currentPlanResult.value,
      newPlanResult.value,
      period,
      row.billing_interval === 'yearly'
    );

    return Result.ok(proration);
  }

  /**
   * Apply proration to subscription change
   */
  async applyProration(
    tenantId: string,
    newPlanName: string,
    stripeSubscriptionId: string
  ): Promise<Result<{
    proration: ProrationResult;
    appliedAt: Date;
  }, Error>> {
    const prorationResult = await this.previewProration(tenantId, newPlanName);
    if (!prorationResult.ok) return Result.err(prorationResult.error);

    const proration = prorationResult.value;
    const now = new Date();

    // Record proration in database
    const insertResult = await this.db.query(
      `INSERT INTO proration_records (
        id, tenant_id, stripe_subscription_id, old_plan, new_plan,
        credit_amount, charge_amount, net_amount, applied_at, created_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, 
        (SELECT plan FROM tenants WHERE id = $1),
        $3, $4, $5, $6, $7, NOW()
      )`,
      [
        tenantId,
        stripeSubscriptionId,
        newPlanName,
        proration.creditAmount,
        proration.chargeAmount,
        proration.netAmount,
        now,
      ]
    );

    if (!insertResult.ok) return Result.err(insertResult.error);

    return Result.ok({
      proration,
      appliedAt: now,
    });
  }

  private buildExplanation(
    currentPlan: Plan,
    newPlan: Plan,
    currentPrice: number,
    newPrice: number,
    daysRemaining: number,
    daysInPeriod: number,
    creditAmount: number,
    chargeAmount: number,
    netAmount: number
  ): string {
    const formatCurrency = (cents: number): string => 
      `$${(Math.abs(cents) / 100).toFixed(2)}`;

    const lines: string[] = [
      `Plan change from ${currentPlan.displayName} to ${newPlan.displayName}`,
      ``,
      `Current period: ${daysRemaining} days remaining out of ${daysInPeriod} days`,
      ``,
      `Credit for unused ${currentPlan.displayName} time: ${formatCurrency(creditAmount)}`,
      `(${formatCurrency(currentPrice)} / ${daysInPeriod} days × ${daysRemaining} days)`,
      ``,
      `Charge for ${newPlan.displayName} remaining time: ${formatCurrency(chargeAmount)}`,
      `(${formatCurrency(newPrice)} / ${daysInPeriod} days × ${daysRemaining} days)`,
      ``,
    ];

    if (netAmount > 0) {
      lines.push(`Net charge: ${formatCurrency(netAmount)}`);
    } else if (netAmount < 0) {
      lines.push(`Net credit: ${formatCurrency(netAmount)} (applied to next invoice)`);
    } else {
      lines.push(`No additional charge or credit`);
    }

    return lines.join('\n');
  }
}
