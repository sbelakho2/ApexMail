/**
 * Comprehensive fail-first tests for billing, plans, and PAYG calculations.
 * Tests are designed to break first if any invariant is violated.
 */
import { describe, expect, it, vi } from 'vitest';

vi.mock('@apexmail/lib', () => ({
  Result: {
    ok: <T>(value: T) => ({ ok: true, value }),
    err: (error: unknown) => ({ ok: false, error }),
  },
}));

vi.mock('@apexmail/lib/logger', () => ({
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

const { calculatePaygCost, calculateOverageCost, PAYG_PRICING } = await import('../services/plans.js');

// ── PAYG Cost Calculation ──────────────────────────────────────

describe('PAYG cost calculation — fail-first', () => {
  it('zero usage produces zero cost', () => {
    const result = calculatePaygCost(0, 0);
    expect(result.totalCostCents).toBe(0);
    expect(result.emailCostCents).toBe(0);
    expect(result.apiCostCents).toBe(0);
    expect(result.totalCostUsd).toBe('$0.00');
  });

  it('single email costs less than 1 cent but rounds to minimum', () => {
    const result = calculatePaygCost(1, 0);
    expect(result.emailCostCents).toBe(0);
    expect(result.totalCostCents).toBe(0);
  });

  it('5 emails cost exactly 1 cent (0.5 millicents each = 500mc = floor to 0 or round to 1)', () => {
    const result = calculatePaygCost(5, 0);
    // 5 * 100 millicents = 500mc → roundMillicentsToCents(500) = floor((500+500)/1000) = 1
    expect(result.emailCostCents).toBe(1);
  });

  it('first 10k emails at tier 1 price = $10.00', () => {
    const result = calculatePaygCost(10_000, 0);
    expect(result.emailCostCents).toBe(1000); // $10.00
    expect(result.totalCostUsd).toBe('$10.00');
  });

  it('10,001 emails cross into tier 2', () => {
    const result = calculatePaygCost(10_001, 0);
    // 10,000 * 100mc = 1,000,000mc = 1000 cents
    // 1 * 80mc = 80mc → rounds to 0 cents
    expect(result.emailCostCents).toBe(1000);
  });

  it('100,000 emails span all of tier 1 and tier 2', () => {
    const result = calculatePaygCost(100_000, 0);
    // 10,000 * 100 + 90,000 * 80 = 1,000,000 + 7,200,000 = 8,200,000mc = 8200 cents
    expect(result.emailCostCents).toBe(8200);
    expect(result.totalCostUsd).toBe('$82.00');
  });

  it('API calls under free limit cost nothing', () => {
    const result = calculatePaygCost(0, 99_999);
    expect(result.apiCostCents).toBe(0);
  });

  it('API calls exactly at free limit cost nothing', () => {
    const result = calculatePaygCost(0, 100_000);
    expect(result.apiCostCents).toBe(0);
  });

  it('1 API call over free limit costs $0.10 (minimum charge per 1000)', () => {
    const result = calculatePaygCost(0, 100_001);
    expect(result.apiCostCents).toBe(10); // $0.10 = ceil(1/1000) * 10
  });

  it('1000 API calls over free limit costs $0.10', () => {
    const result = calculatePaygCost(0, 101_000);
    expect(result.apiCostCents).toBe(10);
  });

  it('email + API combined cost sums correctly', () => {
    const result = calculatePaygCost(10_000, 101_000);
    expect(result.emailCostCents).toBe(1000);
    expect(result.apiCostCents).toBe(10);
    expect(result.totalCostCents).toBe(1010);
  });

  it('USD string formatting handles zero correctly', () => {
    const result = calculatePaygCost(0, 0);
    expect(result.totalCostUsd).toBe('$0.00');
  });

  it('USD string formatting handles cents < 10', () => {
    const result = calculatePaygCost(5, 0);
    expect(result.totalCostUsd).toBe('$0.01');
  });

  it('USD string formatting handles exact dollars', () => {
    const result = calculatePaygCost(10_000, 0);
    expect(result.totalCostUsd).toBe('$10.00');
  });
});

// ── Overage Cost Calculation ───────────────────────────────────

describe('Overage cost calculation — fail-first', () => {
  it('within limit returns zero overage', () => {
    expect(calculateOverageCost(1000, 5000)).toBe(0);
  });

  it('exactly at limit returns zero overage', () => {
    expect(calculateOverageCost(5000, 5000)).toBe(0);
  });

  it('1 email over limit = ceil(1 * 40 / 1000) = 1 cent', () => {
    expect(calculateOverageCost(5001, 5000)).toBe(1);
  });

  it('25 emails over limit = ceil(25 * 40 / 1000) = 1 cent', () => {
    expect(calculateOverageCost(5025, 5000)).toBe(1);
  });

  it('1000 emails over = ceil(1000 * 40 / 1000) = 40 cents', () => {
    expect(calculateOverageCost(6000, 5000)).toBe(40);
  });

  it('unlimited plan (-1) has no overage even with huge usage', () => {
    expect(calculateOverageCost(999_999_999, -1)).toBe(0);
  });

  it('zero limit returns zero overage (suspended plan)', () => {
    expect(calculateOverageCost(100, 0)).toBe(0);
  });

  it('negative emails throws error', () => {
    expect(() => calculateOverageCost(-1, 5000)).toThrow();
  });

  it('non-number emailLimit throws error', () => {
    expect(() => calculateOverageCost(100, 'bad' as unknown as number)).toThrow();
  });
});

// ── PAYG Pricing Tiers ─────────────────────────────────────────

describe('PAYG pricing configuration — fail-first', () => {
  it('has exactly 4 email tiers', () => {
    expect(PAYG_PRICING.emailPricing.length).toBe(4);
  });

  it('last tier has upTo = Infinity', () => {
    const lastTier = PAYG_PRICING.emailPricing[PAYG_PRICING.emailPricing.length - 1]!;
    expect(lastTier.upTo).toBe(Infinity);
  });

  it('tiers are in ascending order by upTo', () => {
    for (let i = 1; i < PAYG_PRICING.emailPricing.length; i++) {
      const current = PAYG_PRICING.emailPricing[i]!;
      const previous = PAYG_PRICING.emailPricing[i - 1]!;
      expect(current.upTo).toBeGreaterThan(previous.upTo);
    }
  });

  it('tier prices decrease with volume (volume discount)', () => {
    for (let i = 1; i < PAYG_PRICING.emailPricing.length; i++) {
      const current = PAYG_PRICING.emailPricing[i]!;
      const previous = PAYG_PRICING.emailPricing[i - 1]!;
      expect(current.pricePerEmailMillicents).toBeLessThan(previous.pricePerEmailMillicents);
    }
  });

  it('all tier prices are positive', () => {
    for (const tier of PAYG_PRICING.emailPricing) {
      expect(tier.pricePerEmailMillicents).toBeGreaterThan(0);
    }
  });

  it('API free calls per month is positive', () => {
    expect(PAYG_PRICING.apiPricing.freeCallsPerMonth).toBeGreaterThan(0);
  });

  it('API price per thousand calls is positive', () => {
    expect(PAYG_PRICING.apiPricing.pricePerThousandCallsCents).toBeGreaterThan(0);
  });
});