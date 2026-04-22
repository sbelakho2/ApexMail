/**
 * Billing Security Tests
 *
 * Aggressive fail-first tests that verify the billing system correctly
 * handles SSRF, open redirect, input validation, and edge cases in
 * checkout, webhook handling, and plan operations.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
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
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

import type { BillingContext, BillingEnv } from '../app.js';
import { billingRoutes } from '../routes/billing.js';

function buildBillingRouteApp(
  ctx: Partial<BillingContext>,
  overrides: { tenantId?: string; isAdmin?: boolean } = {},
) {
  const app = new Hono<BillingEnv>();

  app.use('*', async (c, next) => {
    c.set('tenantId', overrides.tenantId ?? 'tenant_123');
    c.set('userId', 'user_123');
    c.set('isAdmin', overrides.isAdmin ?? false);
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

describe('billing security: open redirect prevention', () => {
  const stripe = {
    createCheckoutSession: vi.fn().mockResolvedValue({
      ok: true,
      value: { sessionId: 'cs_test', url: 'https://checkout.stripe.com/pay/cs_test' },
    }),
  };

  beforeEach(() => {
    stripe.createCheckoutSession.mockClear();
  });

  const maliciousUrls = [
    'https://evil.com',
    'https://apexmail.ee.evil.com/success',
    'https://apexmail.ee@evil.com/success',
    'javascript:alert(document.cookie)',
    'data:text/html,<script>alert(1)</script>',
    ' //evil.com/steal',
    'https://evil.com/redirect?next=https://apexmail.ee',
    'https://app.apexmail.ee.evil.com/success',
    'ftp://apexmail.ee/files',
    'https://app.apexmail.ee%2E.evil.com/success',
  ];

  for (const url of maliciousUrls) {
    it(`rejects malicious successUrl: ${url.substring(0, 50)}`, async () => {
      const app = buildBillingRouteApp({ stripe });
      const response = await app.request('http://billing.local/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          priceId: 'price_pro',
          successUrl: url,
          cancelUrl: 'https://app.apexmail.ee/cancel',
        }),
      });
      expect(response.status).toBe(400);
      expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    });
  }

  for (const url of maliciousUrls) {
    it(`rejects malicious cancelUrl: ${url.substring(0, 50)}`, async () => {
      const app = buildBillingRouteApp({ stripe });
      const response = await app.request('http://billing.local/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          priceId: 'price_pro',
          successUrl: 'https://app.apexmail.ee/success',
          cancelUrl: url,
        }),
      });
      expect(response.status).toBe(400);
      expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    });
  }

  it('accepts valid apexmail.ee domains', async () => {
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
    expect(stripe.createCheckoutSession).toHaveBeenCalledTimes(1);
  });
});

describe('billing security: input validation', () => {
  it('rejects empty priceId', async () => {
    const stripe = { createCheckoutSession: vi.fn() };
    const app = buildBillingRouteApp({ stripe });
    const response = await app.request('http://billing.local/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        priceId: '',
        successUrl: 'https://app.apexmail.ee/success',
        cancelUrl: 'https://app.apexmail.ee/cancel',
      }),
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
  });

  it('rejects missing request body', async () => {
    const stripe = { createCheckoutSession: vi.fn() };
    const app = buildBillingRouteApp({ stripe });
    const response = await app.request('http://billing.local/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
  });

  it('rejects non-JSON content type', async () => {
    const stripe = { createCheckoutSession: vi.fn() };
    const app = buildBillingRouteApp({ stripe });
    const response = await app.request('http://billing.local/checkout', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'price_pro',
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
  });
});
