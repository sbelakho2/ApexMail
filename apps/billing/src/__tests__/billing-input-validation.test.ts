import { describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import type { BillingContext, BillingEnv } from '../app.js';
import { billingRoutes } from '../routes/billing.js';

vi.mock('@apexmail/db', () => ({
  withTransaction: vi.fn(),
}));

vi.mock('../lib/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

vi.mock('../services/plans.js', () => ({
  calculateOverageCost: vi.fn(() => 400),
  calculatePaygCost: vi.fn(() => ({ totalCostCents: 500, totalCostUsd: '$5.00' })),
  PAYG_PRICING: {
    emailPricing: [],
    apiPricing: { perThousandCallsCents: 10 },
    minimumMonthlyCharge: 0,
  },
}));

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
  return app;
}

describe('billing route input validation', () => {
  it.each([
    '/alerts',
    '/payg/estimate',
    '/overage/estimate',
    '/switch-plan',
    '/cancel',
  ])('returns 400 for malformed JSON on %s', async (path) => {
    const app = buildBillingRouteApp({});
    const response = await app.request(`http://billing.local${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{',
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: 'Invalid JSON body' });
  });

  it('returns a structured 400 for invalid PAYG estimate input', async () => {
    const app = buildBillingRouteApp({});
    const response = await app.request('http://billing.local/payg/estimate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ emailsSent: -1 }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: 'Validation failed' });
  });

  it('returns a structured 400 for invalid switch-plan input', async () => {
    const app = buildBillingRouteApp({});
    const response = await app.request('http://billing.local/switch-plan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ planName: 'starter', billingInterval: 'weekly' }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: 'Validation failed' });
  });
});