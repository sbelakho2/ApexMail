import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Plan } from '../services/plans.js';
import type { SubscriptionPeriod } from '../services/proration.js';
import { MS_PER_DAY } from '../lib/constants.js';

// Pure function versions of ProrationEngine methods for testing
function calculateProration(
  currentPlan: Plan,
  newPlan: Plan,
  currentPeriod: SubscriptionPeriod,
  isYearly: boolean
) {
  const currentPriceNumerator = isYearly ? currentPlan.priceYearly : currentPlan.priceMonthly;
  const newPriceNumerator = isYearly ? newPlan.priceYearly : newPlan.priceMonthly;
  const priceDivisor = isYearly ? 12 : 1;

  const { daysInPeriod, daysRemaining } = currentPeriod;

  if (daysInPeriod <= 0) {
    throw new Error('Invalid period: daysInPeriod must be greater than 0');
  }

  const periodDivisor = daysInPeriod * priceDivisor;
  const creditAmount = Math.round((currentPriceNumerator * daysRemaining) / periodDivisor);
  const chargeAmount = Math.round((newPriceNumerator * daysRemaining) / periodDivisor);
  const netAmount = chargeAmount - creditAmount;

  return {
    creditAmount,
    chargeAmount,
    netAmount,
    currentPlanDaysRemaining: daysRemaining,
    newPlanDaysInPeriod: daysRemaining,
    effectiveDate: new Date(),
  };
}

function calculatePeriod(start: Date, end: Date, now: Date): SubscriptionPeriod {
  const daysInPeriod = Math.ceil((end.getTime() - start.getTime()) / MS_PER_DAY);
  const daysElapsed = Math.ceil((now.getTime() - start.getTime()) / MS_PER_DAY);
  const daysRemaining = Math.max(0, daysInPeriod - daysElapsed);

  return { start, end, daysInPeriod, daysElapsed, daysRemaining };
}

// Test plans
const freePlan: Plan = {
  name: 'free',
  displayName: 'Free',
  description: 'Free tier',
  priceMonthly: 0,
  priceYearly: 0,
  emailsIncluded: 1000,
  additionalEmailPrice: 0,
  features: {},
  isActive: true,
};

const starterPlan: Plan = {
  name: 'starter',
  displayName: 'Starter',
  description: 'Starter plan',
  priceMonthly: 2900,
  priceYearly: 29000,
  emailsIncluded: 10000,
  additionalEmailPrice: 100,
  features: {},
  isActive: true,
};

const proPlan: Plan = {
  name: 'pro',
  displayName: 'Pro',
  description: 'Pro plan',
  priceMonthly: 9900,
  priceYearly: 99000,
  emailsIncluded: 50000,
  additionalEmailPrice: 50,
  features: {},
  isActive: true,
};

describe('Proration calculations', () => {
  describe('calculateProration', () => {
    const fullPeriod: SubscriptionPeriod = {
      start: new Date('2024-01-01'),
      end: new Date('2024-01-31'),
      daysInPeriod: 30,
      daysElapsed: 15,
      daysRemaining: 15,
    };

    it('calculates upgrade from free to starter (monthly)', () => {
      const result = calculateProration(freePlan, starterPlan, fullPeriod, false);

      expect(result.creditAmount).toBe(0); // Free plan, no credit
      expect(result.chargeAmount).toBe(1450); // $29 * 15/30 = $14.50
      expect(result.netAmount).toBe(1450); // Customer pays $14.50
    });

    it('calculates upgrade from starter to pro (monthly)', () => {
      const result = calculateProration(starterPlan, proPlan, fullPeriod, false);

      // Credit: $29 * 15/30 = $14.50
      expect(result.creditAmount).toBe(1450);
      // Charge: $99 * 15/30 = $49.50
      expect(result.chargeAmount).toBe(4950);
      // Net: $49.50 - $14.50 = $35.00
      expect(result.netAmount).toBe(3500);
    });

    it('calculates downgrade from pro to starter (monthly)', () => {
      const result = calculateProration(proPlan, starterPlan, fullPeriod, false);

      // Credit: $99 * 15/30 = $49.50
      expect(result.creditAmount).toBe(4950);
      // Charge: $29 * 15/30 = $14.50
      expect(result.chargeAmount).toBe(1450);
      // Net: $14.50 - $49.50 = -$35.00 (credit to customer)
      expect(result.netAmount).toBe(-3500);
    });

    it('handles yearly pricing with proration', () => {
      const result = calculateProration(starterPlan, proPlan, fullPeriod, true);

      // Yearly prices divided by 12 for monthly proration
      // Credit: $290/12 * 15/30 ≈ $12.08
      expect(result.creditAmount).toBe(1208);
      // Charge: $990/12 * 15/30 ≈ $41.25
      expect(result.chargeAmount).toBe(4125);
      // Net: ~$29.17
      expect(result.netAmount).toBe(2917);
    });

    it('handles zero days remaining', () => {
      const endOfPeriod: SubscriptionPeriod = {
        ...fullPeriod,
        daysElapsed: 30,
        daysRemaining: 0,
      };

      const result = calculateProration(starterPlan, proPlan, endOfPeriod, false);

      expect(result.creditAmount).toBe(0);
      expect(result.chargeAmount).toBe(0);
      expect(result.netAmount).toBe(0);
    });

    it('throws on invalid period with zero days', () => {
      const invalidPeriod: SubscriptionPeriod = {
        ...fullPeriod,
        daysInPeriod: 0,
      };

      expect(() => calculateProration(freePlan, starterPlan, invalidPeriod, false))
        .toThrow('Invalid period: daysInPeriod must be greater than 0');
    });
  });

  describe('calculatePeriod', () => {
    it('calculates period at start of cycle', () => {
      const start = new Date('2024-01-01');
      const end = new Date('2024-01-31');
      const now = new Date('2024-01-01');

      const period = calculatePeriod(start, end, now);

      expect(period.daysInPeriod).toBe(30);
      expect(period.daysElapsed).toBe(0);
      expect(period.daysRemaining).toBe(30);
    });

    it('calculates period mid-cycle', () => {
      const start = new Date('2024-01-01');
      const end = new Date('2024-01-31');
      const now = new Date('2024-01-16');

      const period = calculatePeriod(start, end, now);

      expect(period.daysInPeriod).toBe(30);
      expect(period.daysElapsed).toBe(15);
      expect(period.daysRemaining).toBe(15);
    });

    it('calculates period at end of cycle', () => {
      const start = new Date('2024-01-01');
      const end = new Date('2024-01-31');
      const now = new Date('2024-01-31');

      const period = calculatePeriod(start, end, now);

      expect(period.daysInPeriod).toBe(30);
      expect(period.daysElapsed).toBe(30);
      expect(period.daysRemaining).toBe(0);
    });

    it('clamps remaining days to zero when past end', () => {
      const start = new Date('2024-01-01');
      const end = new Date('2024-01-31');
      const now = new Date('2024-02-05'); // Past end

      const period = calculatePeriod(start, end, now);

      expect(period.daysRemaining).toBe(0);
    });
  });
});
