import { beforeEach, describe, expect, it, vi } from 'vitest';

const stripeCreate = vi.fn();

vi.mock('@apexmail/lib', () => {
  return {
    Result: {
      ok(value: unknown) {
        return { ok: true, value };
      },
      err(error: Error) {
        return { ok: false, error };
      },
    },
  };
});

vi.mock('@apexmail/lib/logger', () => {
  return {
    createLogger() {
      return {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        debug: vi.fn(),
      };
    },
  };
});

vi.mock('../lib/stripe-client.js', () => {
  return {
    getStripe() {
      return {
        subscriptionItems: {
          create: stripeCreate,
          del: vi.fn(),
        },
      };
    },
  };
});

vi.mock('../config.js', () => {
  return {
    config: {
      stripeDedicatedIpPriceId: 'price_dedicated_ip',
    },
  };
});

import { DedicatedIpBillingService } from '../services/dedicated-ip-billing.js';

describe('DedicatedIpBillingService', () => {
  let db: any;

  beforeEach(() => {
    stripeCreate.mockReset();
    stripeCreate.mockRejectedValue(new Error('stripe unavailable'));

    db = {
      query: vi.fn(async (sql: string) => {
        if (sql.includes('FROM stripe_subscriptions')) {
          return {
            ok: true,
            value: {
              rows: [
                {
                  stripe_subscription_id: 'sub_123',
                  stripe_customer_id: 'cus_123',
                },
              ],
            },
          };
        }

        return {
          ok: true,
          value: {
            rows: [],
          },
        };
      }),
    };
  });

  it('stops hitting Stripe once the circuit breaker opens', async () => {
    const service = new DedicatedIpBillingService(db);
    const ipRow = {
      id: 'ip_123',
      tenant_id: 'tenant_123',
      ip_address: '203.0.113.10',
      billing_status: 'pending_charge',
      stripe_subscription_item_id: null,
    };

    for (let attempt = 0; attempt < 6; attempt += 1) {
      await service['chargeForIp'](ipRow);
    }

    expect(stripeCreate).toHaveBeenCalledTimes(5);
  });
});