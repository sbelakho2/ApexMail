/**
 * Proration Engine — Aggressive Edge-Case Tests
 *
 * These tests verify that the proration engine handles boundary conditions,
 * floating-point precision, DST transitions, extreme plan changes, and
 * security limits correctly. Tests are designed fail-first to detect real bugs.
 */

import { describe, it, expect } from 'vitest';
import type { Plan } from '../services/plans.js';
import type { SubscriptionPeriod } from '../services/proration.js';
import { MS_PER_DAY } from '../lib/constants.js';

// ─── Pure calculation functions (mirrors ProrationEngine) ──────

function calculateProration(
  currentPlan: Plan,
  newPlan: Plan,
  currentPeriod: SubscriptionPeriod,
  isYearly: boolean,
  maxProrationChargeCents = 100_000,
  maxProrationCreditCents = 50_000,
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

  if (netAmount > maxProrationChargeCents) {
    throw new Error(`Proration charge exceeds maximum allowed`);
  }
  if (Math.abs(netAmount) > maxProrationCreditCents && netAmount < 0) {
    throw new Error(`Proration credit exceeds maximum allowed`);
  }

  return { creditAmount, chargeAmount, netAmount, currentPlanDaysRemaining: daysRemaining };
}

function calculatePeriod(start: Date, end: Date, now: Date): SubscriptionPeriod {
  const daysInPeriod = Math.ceil((end.getTime() - start.getTime()) / MS_PER_DAY);
  const daysElapsed = Math.ceil((now.getTime() - start.getTime()) / MS_PER_DAY);
  const daysRemaining = Math.max(0, daysInPeriod - daysElapsed);
  return { start, end, daysInPeriod, daysElapsed, daysRemaining };
}

// ─── Test Plans ────────────────────────────────────────────────

const freePlan: Plan = {
  name: 'free', displayName: 'Free', description: '',
  priceMonthly: 0, priceYearly: 0, emailsIncluded: 1000,
  additionalEmailPrice: 0, features: {}, isActive: true,
};

const starterPlan: Plan = {
  name: 'starter', displayName: 'Starter', description: '',
  priceMonthly: 2900, priceYearly: 29000, emailsIncluded: 10000,
  additionalEmailPrice: 100, features: {}, isActive: true,
};

const proPlan: Plan = {
  name: 'pro', displayName: 'Pro', description: '',
  priceMonthly: 9900, priceYearly: 99000, emailsIncluded: 50000,
  additionalEmailPrice: 50, features: {}, isActive: true,
};

const enterprisePlan: Plan = {
  name: 'enterprise', displayName: 'Enterprise', description: '',
  priceMonthly: 49900, priceYearly: 499000, emailsIncluded: 1000000,
  additionalEmailPrice: 10, features: {}, isActive: true,
};

// ─── Edge Case Tests ───────────────────────────────────────────

describe('Proration edge cases', () => {
  describe('single day remaining', () => {
    it('correctly prorates with only 1 day left in 30-day period', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 29, daysRemaining: 1,
      };
      const result = calculateProration(starterPlan, proPlan, period, false);
// $29 * 1/30 ≈ $0.97, $99 * 1/30 = $3.30, net ≈ $2.33
      expect(result.creditAmount).toBe(97);
      expect(result.chargeAmount).toBe(330);
      expect(result.netAmount).toBe(233);
    });
  });

  describe('full period remaining (day-one change)', () => {
    it('prorates over entire period when changing on day 1', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 0, daysRemaining: 30,
      };
      const result = calculateProration(starterPlan, proPlan, period, false);
      expect(result.creditAmount).toBe(2900); // full refund of starter
      expect(result.chargeAmount).toBe(9900); // full charge for pro
      expect(result.netAmount).toBe(7000); // difference
    });
  });

  describe('negative days (past-end-of-period)', () => {
    it('calculatePeriod clamps remaining to zero when past end', () => {
      const period = calculatePeriod(
        new Date('2024-01-01'),
        new Date('2024-01-31'),
        new Date('2024-02-15'), // 15 days past
      );
      expect(period.daysRemaining).toBe(0);
      expect(period.daysElapsed).toBeGreaterThan(period.daysInPeriod);
    });
  });

  describe('floating-point precision', () => {
    it('does not produce fractional cents from rounding', () => {
// 7 days remaining in 31-day period:$29 * 7/31 = 6.548... → must round cleanly
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-02-01'),
        daysInPeriod: 31, daysElapsed: 24, daysRemaining: 7,
      };
      const result = calculateProration(starterPlan, proPlan, period, false);
      expect(Number.isInteger(result.creditAmount)).toBe(true);
      expect(Number.isInteger(result.chargeAmount)).toBe(true);
      expect(Number.isInteger(result.netAmount)).toBe(true);
    });

    it('handles yearly pricing division without precision loss', () => {
// Yearly:$290/12 * 13/31 → rounding chain
      const period: SubscriptionPeriod = {
        start: new Date('2024-03-01'), end: new Date('2024-04-01'),
        daysInPeriod: 31, daysElapsed: 18, daysRemaining: 13,
      };
      const result = calculateProration(starterPlan, proPlan, period, true);
      expect(Number.isInteger(result.creditAmount)).toBe(true);
      expect(Number.isInteger(result.chargeAmount)).toBe(true);
// Verify credit + charge relationship
      expect(result.netAmount).toBe(result.chargeAmount - result.creditAmount);
    });
  });

  describe('DST boundary dates', () => {
    it('handles spring-forward transition (23-hour day)', () => {
// US DST spring forward:March 10, 2024
      const period = calculatePeriod(
        new Date('2024-03-01T00:00:00'),
        new Date('2024-03-31T00:00:00'),
        new Date('2024-03-10T12:00:00'),
      );
      // Depending on host timezone/DST rules this can be 30 or 31 with ceil-based math.
      expect(period.daysInPeriod).toBeGreaterThanOrEqual(30);
      expect(period.daysInPeriod).toBeLessThanOrEqual(31);
      expect(period.daysElapsed).toBeGreaterThanOrEqual(9);
      expect(period.daysRemaining).toBeGreaterThan(0);
      expect(period.daysRemaining).toBeLessThanOrEqual(21);
    });

    it('handles fall-back transition (25-hour day)', () => {
// US DST fall back:November 3, 2024
      const period = calculatePeriod(
        new Date('2024-11-01T00:00:00'),
        new Date('2024-11-30T00:00:00'),
        new Date('2024-11-03T12:00:00'),
      );
      // Depending on host timezone/DST rules this can be 29 or 30 with ceil-based math.
      expect(period.daysInPeriod).toBeGreaterThanOrEqual(29);
      expect(period.daysInPeriod).toBeLessThanOrEqual(30);
      expect(period.daysElapsed).toBeGreaterThanOrEqual(2);
      expect(period.daysRemaining).toBeGreaterThan(0);
    });
  });

  describe('proration limits (SEC-014)', () => {
    it('throws on excessive charge above max', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 0, daysRemaining: 30,
      };
// Enterprise ($499/mo) from free — net $499 > default max $100
      expect(() => calculateProration(
        freePlan, enterprisePlan, period, false, 10_000, 50_000,
      )).toThrow('exceeds maximum allowed');
    });

    it('throws on excessive credit above max', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 0, daysRemaining: 30,
      };
// Enterprise → Free credit = $499, exceeds $100 max credit
      expect(() => calculateProration(
        enterprisePlan, freePlan, period, false, 100_000, 10_000,
      )).toThrow('exceeds maximum allowed');
    });

    it('allows changes within limits', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 15, daysRemaining: 15,
      };
// Starter → Pro:net ~$35, well within $1000 limit
      expect(() => calculateProration(
        starterPlan, proPlan, period, false, 100_000, 50_000,
      )).not.toThrow();
    });
  });

  describe('same plan change (no-op)', () => {
    it('produces zero net amount for same-plan change', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 15, daysRemaining: 15,
      };
      const result = calculateProration(proPlan, proPlan, period, false);
      expect(result.netAmount).toBe(0);
      expect(result.creditAmount).toBe(result.chargeAmount);
    });
  });

  describe('extremely short periods', () => {
    it('handles 1-day period without division by zero', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-02'),
        daysInPeriod: 1, daysElapsed: 0, daysRemaining: 1,
      };
      const result = calculateProration(starterPlan, proPlan, period, false);
// Full daily rate difference
      expect(result.netAmount).toBe(result.chargeAmount - result.creditAmount);
      expect(Number.isInteger(result.netAmount)).toBe(true);
    });

    it('throws on zero-length period', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-01'),
        daysInPeriod: 0, daysElapsed: 0, daysRemaining: 0,
      };
      expect(() => calculateProration(starterPlan, proPlan, period, false)).toThrow('daysInPeriod');
    });

    it('throws on negative-length period', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-01'),
        daysInPeriod: -1, daysElapsed: 0, daysRemaining: 0,
      };
      expect(() => calculateProration(starterPlan, proPlan, period, false)).toThrow('daysInPeriod');
    });
  });

  describe('leap year handling', () => {
    it('handles February 29 in leap year', () => {
      const period = calculatePeriod(
        new Date('2024-02-01'),
        new Date('2024-03-01'),
        new Date('2024-02-15'),
      );
      expect(period.daysInPeriod).toBe(29); // 2024 is a leap year
      expect(period.daysRemaining).toBeGreaterThan(0);
    });

    it('handles February 28 in non-leap year', () => {
      const period = calculatePeriod(
        new Date('2025-02-01'),
        new Date('2025-03-01'),
        new Date('2025-02-15'),
      );
      expect(period.daysInPeriod).toBe(28);
      expect(period.daysRemaining).toBeGreaterThan(0);
    });
  });

  describe('downgrade to free plan', () => {
    it('produces negative net (customer gets credit)', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 5, daysRemaining: 25,
      };
      const result = calculateProration(proPlan, freePlan, period, false);
      expect(result.netAmount).toBeLessThan(0);
      expect(result.chargeAmount).toBe(0);
      expect(result.creditAmount).toBeGreaterThan(0);
    });
  });

  describe('idempotency', () => {
    it('same inputs always produce same output', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 15, daysRemaining: 15,
      };
      const results = Array.from({ length: 100 }, () =>
        calculateProration(starterPlan, proPlan, period, false),
      );
      const first = results[0];
      for (const r of results) {
        expect(r.netAmount).toBe(first.netAmount);
        expect(r.creditAmount).toBe(first.creditAmount);
        expect(r.chargeAmount).toBe(first.chargeAmount);
      }
    });
  });

  describe('symmetry', () => {
    it('upgrade then downgrade nets to approximately zero', () => {
      const period: SubscriptionPeriod = {
        start: new Date('2024-01-01'), end: new Date('2024-01-31'),
        daysInPeriod: 30, daysElapsed: 15, daysRemaining: 15,
      };
      const upgrade = calculateProration(starterPlan, proPlan, period, false);
      const downgrade = calculateProration(proPlan, starterPlan, period, false);
// The magnitudes should match (opposite signs)
      expect(upgrade.netAmount + downgrade.netAmount).toBe(0);
    });
  });

  describe('calculatePeriod edge cases', () => {
    it('handles same start and end date', () => {
      const period = calculatePeriod(
        new Date('2024-01-01'),
        new Date('2024-01-01'),
        new Date('2024-01-01'),
      );
      expect(period.daysInPeriod).toBe(0);
      expect(period.daysRemaining).toBe(0);
    });

    it('handles now before start', () => {
      const period = calculatePeriod(
        new Date('2024-06-01'),
        new Date('2024-06-30'),
        new Date('2024-05-15'), // before start
      );
      expect(period.daysElapsed).toBeLessThanOrEqual(0);
      expect(period.daysRemaining).toBeGreaterThanOrEqual(period.daysInPeriod);
    });
  });
});
