import { describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { ZodError } from 'zod';

vi.mock('@apexmail/db', () => ({
  withTransaction: vi.fn(),
}));

vi.mock('../services/plans.js', () => ({
  calculateOverageCost: vi.fn(),
  calculatePaygCost: vi.fn(),
  PAYG_PRICING: {},
}));

vi.mock('../lib/logger.js', () => ({
  logger: {
    error: vi.fn(),
  },
}));

import type { BillingContext, BillingEnv } from '../app.js';
import { billingRoutes } from '../routes/billing.js';

function buildBillingRouteApp(ctx: Partial<BillingContext>) {
  const app = new Hono<BillingEnv>();

  app.use('*', async (c, next) => {
    c.set('tenantId', 'tenant_123');
    c.set('userId', 'user_123');
    c.set('isAdmin', false);
    c.set('adminId', '');
    await next();
  });

  app.route('/', billingRoutes(ctx as BillingContext));
  app.onError((err, c) => {
    if (err instanceof ZodError) {
      return c.json({ error: 'Validation error', issues: err.issues }, 400);
    }

    throw err;
  });

  return app;
}

describe('Fix 13: billing redirect allowlist rejects IDN/punycode hosts', () => {
  it('rejects checkout redirects that use punycode labels under apexmail.ee', async () => {
    const stripe = {
      createCheckoutSession: vi.fn().mockResolvedValue({
        ok: true,
        value: {
          sessionId: 'cs_test_123',
          url: 'https://checkout.stripe.com/pay/cs_test_123',
        },
      }),
    };
    const app = buildBillingRouteApp({ stripe });

    const response = await app.request('http://billing.local/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        priceId: 'price_pro',
        successUrl: 'https://xn--paypa1-l2c.apexmail.ee/success',
        cancelUrl: 'https://xn--paypa1-l2c.apexmail.ee/cancel',
      }),
    });

    expect(response.status).toBe(400);
    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
  });
});
