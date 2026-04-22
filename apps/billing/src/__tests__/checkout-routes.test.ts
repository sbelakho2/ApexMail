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

describe('billing checkout routes', () => {
  it('rejects checkout redirects outside apexmail domains', async () => {
    const stripe = {
      createCheckoutSession: vi.fn(),
    };
    const app = buildBillingRouteApp({ stripe });

    const response = await app.request('http://billing.local/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        priceId: 'price_pro',
        successUrl: 'https://apexmail.ee.evil.example/success',
        cancelUrl: 'https://apexmail.ee.evil.example/cancel',
      }),
    });

    expect(response.status).toBe(400);
    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
  });

  it('creates checkout sessions for valid apexmail redirect URLs', async () => {
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
        successUrl: 'https://app.apexmail.ee/settings/billing/success',
        cancelUrl: 'https://app.apexmail.ee/settings/billing/cancel',
      }),
    });

    expect(response.status).toBe(200);
    expect(stripe.createCheckoutSession).toHaveBeenCalledWith(
      'tenant_123',
      'price_pro',
      'https://app.apexmail.ee/settings/billing/success',
      'https://app.apexmail.ee/settings/billing/cancel',
    );
    expect(await response.json()).toEqual({
      sessionId: 'cs_test_123',
      url: 'https://checkout.stripe.com/pay/cs_test_123',
    });
  });
});