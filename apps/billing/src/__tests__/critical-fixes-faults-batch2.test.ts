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

vi.mock('../lib/stripe-client.js', () => ({
  getStripe: () => ({
    webhooks: {
      constructEvent: vi.fn(),
    },
    customers: {
      create: vi.fn(),
      del: vi.fn(),
      retrieve: vi.fn(),
      update: vi.fn(),
    },
    subscriptions: {
      retrieve: vi.fn(),
      update: vi.fn(),
      list: vi.fn(),
      cancel: vi.fn(),
    },
    checkout: {
      sessions: {
        create: vi.fn(),
      },
    },
  }),
}));

vi.mock('../services/stripe-circuit-breaker.js', () => ({
  StripeCircuitBreaker: class {
    async execute<T>(fn: () => Promise<T>): Promise<T> {
      return fn();
    }

    getState(): string {
      return 'closed';
    }
  },
}));

vi.mock('../config.js', () => ({
  config: {
    apiBaseUrl: 'https://api.example.com',
    serviceAuthToken: 'service-auth-token',
  },
  getConfig: () => ({
    stripeWebhookSecret: 'whsec_test',
    apiBaseUrl: 'https://api.example.com',
    serviceAuthToken: 'service-auth-token',
  }),
}));

const { StripeService } = await import('../services/stripe-integration.js');

describe('Fix 8: Stripe subscription sync rejects empty line-item payloads', () => {
  it('fails before DB upsert when subscription.items.data is empty', async () => {
    const db = {
      query: vi
        .fn()
        .mockResolvedValueOnce({ ok: true, value: { rows: [], rowCount: 0 } })
        .mockResolvedValueOnce({ ok: true, value: { rows: [{ subscription_updated: true, tenant_updated: true }], rowCount: 1 } }),
    };

    const service = new StripeService(db as never);

    await expect(
      (service as { handleSubscriptionChange: (subscription: unknown) => Promise<void> }).handleSubscriptionChange({
        id: 'sub_1',
        metadata: { tenant_id: 'ten_1' },
        status: 'trialing',
        customer: 'cus_1',
        items: { data: [] },
        current_period_start: 1_700_000_000,
        current_period_end: 1_700_086_400,
        cancel_at_period_end: false,
        canceled_at: null,
        trial_end: null,
      }),
    ).rejects.toThrow(/line item|price/i);

    expect(db.query).toHaveBeenCalledTimes(1);
  });
});
