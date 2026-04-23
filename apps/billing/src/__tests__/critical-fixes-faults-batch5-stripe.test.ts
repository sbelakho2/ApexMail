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

const customersCreateMock = vi.fn();

vi.mock('../lib/stripe-client.js', () => ({
  getStripe: () => ({
    customers: {
      create: customersCreateMock,
      del: vi.fn(),
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
    webhooks: {
      constructEvent: vi.fn(),
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

describe('Fix 21: getOrCreateCustomer uses deterministic Stripe idempotency key', () => {
  it('passes an idempotency key tied to tenant identity when creating Stripe customers', async () => {
    customersCreateMock.mockResolvedValueOnce({ id: 'cus_new' });

    const db = {
      query: vi
        .fn()
        .mockResolvedValueOnce({ ok: true, value: { rows: [], rowCount: 0 } })
        .mockResolvedValueOnce({
          ok: true,
          value: {
            rowCount: 1,
            rows: [
              {
                id: 'row_1',
                stripe_customer_id: 'cus_new',
                created_at: new Date('2026-01-01T00:00:00.000Z'),
                updated_at: new Date('2026-01-01T00:00:00.000Z'),
              },
            ],
          },
        }),
    };

    const service = new StripeService(db as never);
    const result = await service.getOrCreateCustomer('tenant_123', 'user@example.com', 'User');

    expect(result.ok).toBe(true);
    expect(customersCreateMock).toHaveBeenCalledTimes(1);
    const secondArg = customersCreateMock.mock.calls[0]?.[1] as Record<string, unknown> | undefined;
    expect(secondArg?.idempotencyKey).toBe('customer_create_tenant_123');
  });
});
