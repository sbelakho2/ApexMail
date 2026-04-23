import { describe, expect, it, vi } from 'vitest';

vi.mock('@apexmail/lib', () => ({
  Result: {
    ok: <T>(value: T) => ({ ok: true, value }),
    err: (error: unknown) => ({ ok: false, error: error instanceof Error ? error : new Error(String(error)) }),
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

import { calculatePaygCost } from '../services/plans.js';

describe('Fix 19: PAYG email rounding does not overcharge fractional cents', () => {
  it('does not round 0.6 cents of email usage up to 1 cent', () => {
    const cost = calculatePaygCost(6, 0);

    expect(cost.emailCostCents).toBe(0);
    expect(cost.totalCostCents).toBe(0);
  });
});
