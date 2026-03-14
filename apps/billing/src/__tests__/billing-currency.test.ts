import { describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_BILLING_CURRENCY,
  normalizeBillingCurrency,
  resolveTenantBillingCurrency,
} from '../lib/billing-currency.js';

describe('billing currency helpers', () => {
  it('normalizes valid ISO currency codes', () => {
    expect(normalizeBillingCurrency('eur')).toBe('EUR');
    expect(normalizeBillingCurrency(' usd ')).toBe('USD');
  });

  it('falls back for invalid values', () => {
    expect(normalizeBillingCurrency('')).toBe(DEFAULT_BILLING_CURRENCY);
    expect(normalizeBillingCurrency('EURO')).toBe(DEFAULT_BILLING_CURRENCY);
    expect(normalizeBillingCurrency(undefined)).toBe(DEFAULT_BILLING_CURRENCY);
  });

  it('resolves tenant billing currency from tenant settings', async () => {
    const db = {
      query: vi.fn(async () => ({
        ok: true,
        value: {
          rows: [{ billing_currency: 'gbp' }],
        },
      })),
    };

    await expect(resolveTenantBillingCurrency(db as never, 'tenant_123')).resolves.toBe('GBP');
  });

  it('falls back when tenant settings cannot be loaded', async () => {
    const db = {
      query: vi.fn(async () => ({
        ok: false,
        error: new Error('db unavailable'),
      })),
    };

    await expect(resolveTenantBillingCurrency(db as never, 'tenant_123')).resolves.toBe(DEFAULT_BILLING_CURRENCY);
  });
});