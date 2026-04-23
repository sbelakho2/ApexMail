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

const { calculatePaygCost } = await import('../services/plans.js');

describe('calculatePaygCost monthly rounding contract', () => {
  it('returns zero cost when there is no usage', () => {
    expect(calculatePaygCost(0, 0)).toMatchObject({
      emailCostCents: 0,
      apiCostCents: 0,
      totalCostCents: 0,
      totalCostUsd: '$0.00',
    });
  });

  it('rounds down aggregated monthly email subtotal to avoid fractional-cent overcharge', () => {
    expect(calculatePaygCost(1, 0)).toMatchObject({
      emailCostCents: 0,
      totalCostCents: 0,
      totalCostUsd: '$0.00',
    });

    expect(calculatePaygCost(4, 0)).toMatchObject({
      emailCostCents: 0,
      totalCostCents: 0,
    });

    expect(calculatePaygCost(5, 0)).toMatchObject({
      emailCostCents: 0,
      totalCostCents: 0,
      totalCostUsd: '$0.00',
    });
  });

  it('preserves tiered pricing while still rounding only once at the final subtotal', () => {
    expect(calculatePaygCost(10_000, 0)).toMatchObject({
      emailCostCents: 1000,
      totalCostUsd: '$10.00',
    });

    expect(calculatePaygCost(10_001, 0)).toMatchObject({
      emailCostCents: 1000,
      totalCostUsd: '$10.00',
    });
  });
});