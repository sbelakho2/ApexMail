import { describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';

import type { BillingContext, BillingEnv } from '../app.js';
import { webhooksRoutes } from '../routes/webhooks.js';

function buildWebhookApp(ctx: Partial<BillingContext>) {
  const app = new Hono<BillingEnv>();
  app.route('/', webhooksRoutes(ctx as BillingContext));
  return app;
}

function createRedisMock() {
  const pipeline = {
    setex: vi.fn().mockReturnThis(),
    zadd: vi.fn().mockReturnThis(),
    zremrangebyscore: vi.fn().mockReturnThis(),
    expire: vi.fn().mockReturnThis(),
    exec: vi.fn().mockResolvedValue([]),
  };

  return {
    set: vi.fn(),
    del: vi.fn(),
    pipeline: vi.fn(() => pipeline),
    _pipeline: pipeline,
  };
}

describe('billing webhook routes', () => {
  it('delegates duplicate handling to verified Stripe processing', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({
        ok: true,
        value: { eventType: 'customer.subscription.updated', processed: false },
      }),
    };
    const app = buildWebhookApp({ redis, stripe });

    const response = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'sig_test',
      },
      body: JSON.stringify({ id: 'evt_duplicate' }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
    expect(redis.set).not.toHaveBeenCalled();
    expect(redis.pipeline).not.toHaveBeenCalled();
    expect(stripe.processWebhook).toHaveBeenCalledOnce();
  });

  it('records webhook failures without route-level dedup cleanup', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({
        ok: false,
        error: new Error('signature mismatch'),
      }),
    };
    const app = buildWebhookApp({ redis, stripe });

    const response = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'sig_test',
      },
      body: JSON.stringify({ id: 'evt_retry' }),
    });

    expect(response.status).toBe(400);
    expect(redis.del).not.toHaveBeenCalled();
    expect(redis.pipeline).toHaveBeenCalledOnce();
    expect(redis._pipeline.setex).toHaveBeenCalledOnce();
    expect(stripe.processWebhook).toHaveBeenCalledOnce();
  });
});