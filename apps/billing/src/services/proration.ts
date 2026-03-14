/**
 * Proration Engine
 * Calculates pro-rated charges for plan changes
 */

import { Result } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';
import { PlansService, type Plan } from './plans.js';
import { config } from '../config.js';
import { MS_PER_DAY } from '../lib/constants.js';

export interface ProrationResult {
  creditAmount: number;        // Credit for unused time (in cents)
  chargeAmount: number;        // Charge for new plan (in cents)
  netAmount: number;           // Net charge/credit (positive = charge, negative = credit)
  currentPlanDaysRemaining: number;
  newPlanDaysInPeriod: number;
  effectiveDate: Date;
  explanation: string;
  warnings?: string[];         // SEC-014: Warnings about unusual proration amounts
}

/**
 * SEC-014: Maximum proration limits to prevent unexpected charges
 * These can be overridden via environment variables
 */
function getMaxProrationChargeCents(): number {
  return config.maxProrationChargeCents;
}

function getMaxProrationCreditCents(): number {
  return config.maxProrationCreditCents;
}

function getWarnProrationChargeCents(): number {
  return config.warnProrationChargeCents;
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
    const currentPriceNumerator = isYearly ? currentPlan.priceYearly : currentPlan.priceMonthly;
    const newPriceNumerator = isYearly ? newPlan.priceYearly : newPlan.priceMonthly;
    const priceDivisor = isYearly ? 12 : 1;

    const { daysInPeriod, daysRemaining } = currentPeriod;

    // Guard against division by zero
    if (daysInPeriod <= 0) {
      throw new Error('Invalid period: daysInPeriod must be greater than 0');
    }

    const periodDivisor = daysInPeriod * priceDivisor;

    // Credit for unused days on current plan
    const creditAmount = Math.round((currentPriceNumerator * daysRemaining) / periodDivisor);

    // Charge for remaining days on new plan
    const chargeAmount = Math.round((newPriceNumerator * daysRemaining) / periodDivisor);

    // Net amount (positive = customer pays, negative = customer gets credit)
    const netAmount = chargeAmount - creditAmount;
    const maxProrationChargeCents = getMaxProrationChargeCents();
    const maxProrationCreditCents = getMaxProrationCreditCents();
    const warnProrationChargeCents = getWarnProrationChargeCents();

    // SEC-014: Validate proration amounts against limits
    const warnings: string[] = [];
    
    // Check for excessive charges
    if (netAmount > maxProrationChargeCents) {
      throw new Error(
        `Proration charge exceeds maximum allowed: ` +
        `$${(netAmount / 100).toFixed(2)} > $${(maxProrationChargeCents / 100).toFixed(2)}. ` +
        `Please contact support for assistance with this plan change.`
      );
    }
    
    // Check for excessive credits (potential fraud or error)
    if (Math.abs(netAmount) > maxProrationCreditCents && netAmount < 0) {
      throw new Error(
        `Proration credit exceeds maximum allowed: ` +
        `$${(Math.abs(netAmount) / 100).toFixed(2)} > $${(maxProrationCreditCents / 100).toFixed(2)}. ` +
        `Please contact support for assistance with this plan change.`
      );
    }
    
    // Add warning for high charges (but still within limits)
    if (netAmount > warnProrationChargeCents) {
      warnings.push(
        `This plan change will result in a charge of $${(netAmount / 100).toFixed(2)}. ` +
        `Please confirm this is intended.`
      );
    }

    const explanation = this.buildExplanation(
      currentPlan,
      newPlan,
      Math.round(currentPriceNumerator / priceDivisor),
      Math.round(newPriceNumerator / priceDivisor),
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
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }

  /**
   * Calculate subscription period details
   */
  calculatePeriod(billingCycleStart: Date, billingCycleEnd: Date): SubscriptionPeriod {
    const now = new Date();
    const start = new Date(billingCycleStart);
    const end = new Date(billingCycleEnd);

    const daysInPeriod = Math.ceil((end.getTime() - start.getTime()) / MS_PER_DAY);
    const daysElapsed = Math.ceil((now.getTime() - start.getTime()) / MS_PER_DAY);
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
      status: string;
      billing_cycle_start: Date;
      billing_cycle_end: Date;
      billing_interval: 'monthly' | 'yearly';
    }>(
      `SELECT t.plan, s.status, s.current_period_start AS billing_cycle_start,
              s.current_period_end AS billing_cycle_end,
              s.billing_interval
       FROM tenants t
       LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
       WHERE t.id = $1`,
      [tenantId]
    );

    if (!subResult.ok) return Result.err(subResult.error);

    const row = subResult.value.rows[0];
    if (!row) return Result.err(new Error('Tenant not found'));

    // Validate subscription status is active before allowing plan changes
    if (!row.status || row.status !== 'active') {
      return Result.err(new Error(`Cannot change plans: subscription status is ${row.status || 'unknown'}, must be 'active'`));
    }

    // Validate billing period exists
    if (!row.billing_cycle_start || !row.billing_cycle_end) {
      return Result.err(new Error('No active subscription billing period'));
    }

    // Validate billing cycle dates are not in the past (allow slight tolerance for period end)
    const now = new Date();
    const billingCycleEnd = new Date(row.billing_cycle_end);
    const toleranceMs = 24 * 60 * 60 * 1000; // 24 hour tolerance
    
    if (billingCycleEnd.getTime() + toleranceMs < now.getTime()) {
      return Result.err(new Error('Cannot change plans: billing period has ended. Please wait for the new billing period.'));
    }

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
   * Apply proration to subscription change.
   * Uses FOR UPDATE lock to prevent race conditions between preview and apply
   * during concurrent plan change requests. Added retry logic for SKIP LOCKED
   * returning no rows due to concurrency.
   */
  async applyProration(
    tenantId: string,
    newPlanName: string,
    stripeSubscriptionId: string
  ): Promise<Result<{
    proration: ProrationResult;
    appliedAt: Date;
  }, Error>> {
    // Retry configuration for lock contention
    const MAX_RETRIES = 3;
    const RETRY_DELAY_MS = 100;
    
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      // FIX-PRORATION-ATOMIC: Lock the subscription row to prevent concurrent modifications
      const lockResult = await this.db.query<{
        plan: string;
        status: string;
        billing_cycle_start: Date;
        billing_cycle_end: Date;
        billing_interval: 'monthly' | 'yearly';
      }>(
        `SELECT t.plan, s.status, s.current_period_start AS billing_cycle_start,
                s.current_period_end AS billing_cycle_end,
                s.billing_interval
         FROM tenants t
         LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
         WHERE t.id = $1
         FOR UPDATE OF t, s SKIP LOCKED`,
        [tenantId]
      );

      if (!lockResult.ok) return Result.err(lockResult.error);

      const row = lockResult.value.rows[0];
      if (!row) {
        // Row might be locked by another operation, retry with backoff
        if (attempt < MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS * attempt));
          continue;
        }
        return Result.err(new Error('Tenant not found or locked by another operation (retries exhausted)'));
      }

      // Validate subscription status is active
      if (!row.status || row.status !== 'active') {
        return Result.err(new Error(`Cannot change plans: subscription status is ${row.status || 'unknown'}, must be 'active'`));
      }

      // Validate billing period exists
      if (!row.billing_cycle_start || !row.billing_cycle_end) {
        return Result.err(new Error('No active subscription billing period'));
      }

      // Get plans
      const currentPlanResult = await this.plans.getPlanByName(row.plan);
      if (!currentPlanResult.ok) return Result.err(currentPlanResult.error);
      if (!currentPlanResult.value) return Result.err(new Error('Current plan not found'));

      const newPlanResult = await this.plans.getPlanByName(newPlanName);
      if (!newPlanResult.ok) return Result.err(newPlanResult.error);
      if (!newPlanResult.value) return Result.err(new Error('New plan not found'));

      // Calculate period and proration
      const period = this.calculatePeriod(row.billing_cycle_start, row.billing_cycle_end);
      const proration = this.calculateProration(
        currentPlanResult.value,
        newPlanResult.value,
        period,
        row.billing_interval === 'yearly'
      );

      const now = new Date();

      // Record proration in database (within the locked transaction)
      const insertResult = await this.db.query(
        `INSERT INTO proration_records (
          id, tenant_id, stripe_subscription_id, old_plan, new_plan,
          credit_amount, charge_amount, net_amount, applied_at, created_at
        )
        VALUES (
          gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW()
        )`,
        [
        tenantId,
        stripeSubscriptionId,
        row.plan,
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
    
    // Unreachable - all retry paths return above
    return Result.err(new Error('Unexpected state in proration retry loop'));
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
