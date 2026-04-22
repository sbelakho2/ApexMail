/**
 * Fail-first tests for webhook routes.
 * These tests aggressively probe edge cases and security-sensitive paths.
 * Each test is designed to catch a specific class of bug.
 */
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

describe('webhook fail-first: missing signature', () => {
  it('rejects POST without stripe-signature header with 400', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'evt_no_sig' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('Missing stripe-signature');
    // Must NOT call stripe processing when signature is missing
    expect(stripe.processWebhook).not.toHaveBeenCalled();
    // Must log to dead letter queue
    expect(redis.pipeline).toHaveBeenCalledOnce();
  });
});

describe('webhook fail-first: invalid JSON', () => {
  it('rejects malformed JSON body with 400', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_123' },
      body: 'not valid json {{{',
    });

    expect(res.status).toBe(400);
    expect(stripe.processWebhook).not.toHaveBeenCalled();
  });
});

describe('webhook fail-first: missing event ID', () => {
  it('rejects JSON without id field with 400', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_123' },
      body: JSON.stringify({ type: 'invoice.paid', data: {} }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('Missing event ID');
    expect(stripe.processWebhook).not.toHaveBeenCalled();
  });

  it('rejects JSON with null id field with 400', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_123' },
      body: JSON.stringify({ id: null, type: 'invoice.paid' }),
    });

    expect(res.status).toBe(400);
    expect(stripe.processWebhook).not.toHaveBeenCalled();
  });

  it('rejects JSON with empty string id with 400', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_123' },
      body: JSON.stringify({ id: '', type: 'invoice.paid' }),
    });

    expect(res.status).toBe(400);
    expect(stripe.processWebhook).not.toHaveBeenCalled();
  });
});

describe('webhook fail-first: verified duplicate handling', () => {
  it('routes duplicate-looking events through Stripe verification and processing', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({
        ok: true,
        value: { eventType: 'customer.subscription.updated', processed: false },
      }),
    };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_dup' },
      body: JSON.stringify({ id: 'evt_known_duplicate' }),
    });

    expect(res.status).toBe(200);
    expect(stripe.processWebhook).toHaveBeenCalledOnce();
    expect(redis.set).not.toHaveBeenCalled();
    expect(redis.pipeline).not.toHaveBeenCalled();
  });
});

describe('webhook fail-first: processing failure cleans up', () => {
  it('records processing failure without route-level dedup cleanup', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({
        ok: false,
        error: new Error('signature verification failed'),
      }),
    };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_bad' },
      body: JSON.stringify({ id: 'evt_will_fail' }),
    });

    expect(res.status).toBe(400);
    expect(redis.del).not.toHaveBeenCalled();
    // Dead letter queue must capture the failure
    expect(redis._pipeline.setex).toHaveBeenCalledWith(
      expect.stringMatching(/^stripe:deadletter:event:/),
      35 * 24 * 60 * 60,
      expect.any(String),
    );
  });

  it('adds failed event to dead letter queue with correct metadata', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({
        ok: false,
        error: new Error('test error message'),
      }),
    };
    const app = buildWebhookApp({ redis, stripe });

    await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_meta' },
      body: JSON.stringify({ id: 'evt_metadata_check' }),
    });

    const [, , payload] = redis._pipeline.setex.mock.calls.at(-1) ?? [];
    expect(payload).toBeDefined();
    const entry = JSON.parse(String(payload));
    expect(entry.reason).toBe('processing_failed');
    expect(entry.eventId).toBe('evt_metadata_check');
    expect(entry.error).toBe('test error message');
    expect(entry.occurredAt).toBeDefined();
  });
});

describe('webhook fail-first: dead letter retention', () => {
  it('stores dead letters with TTL-backed retention instead of lossy list trimming', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({
        ok: false,
        error: new Error('fail'),
      }),
    };
    const app = buildWebhookApp({ redis, stripe });

    await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_trim' },
      body: JSON.stringify({ id: 'evt_trim_test' }),
    });

    expect(redis._pipeline.zadd).toHaveBeenCalledWith(
      'stripe:deadletter:index',
      expect.any(Number),
      expect.stringMatching(/^stripe:deadletter:event:/),
    );
    expect(redis._pipeline.zremrangebyscore).toHaveBeenCalledWith(
      'stripe:deadletter:index',
      0,
      expect.any(Number),
    );
    expect(redis._pipeline.expire).toHaveBeenCalledWith('stripe:deadletter:index', 35 * 24 * 60 * 60);
  });
});

describe('webhook fail-first: successful processing', () => {
  it('returns 200 and does NOT touch dead letter queue on success', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({ ok: true }),
    };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_ok' },
      body: JSON.stringify({ id: 'evt_success' }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ received: true });
    // Dead letter queue must NOT be touched on success
    expect(redis.pipeline).not.toHaveBeenCalled();
    expect(redis.del).not.toHaveBeenCalled();
  });
});

describe('webhook fail-first: security edge cases', () => {
  it('rejects GET requests to stripe endpoint', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'GET',
    });

    // GET should not match POST route — 404
    expect(res.status).toBe(404);
    expect(stripe.processWebhook).not.toHaveBeenCalled();
  });

  it('handles empty body gracefully', async () => {
    const redis = createRedisMock();
    const stripe = { processWebhook: vi.fn() };
    const app = buildWebhookApp({ redis, stripe });

    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_empty' },
      body: '',
    });

    // Empty body is not valid JSON
    expect(res.status).toBe(400);
    expect(stripe.processWebhook).not.toHaveBeenCalled();
  });

  it('handles very large event ID without error', async () => {
    const redis = createRedisMock();
    const stripe = {
      processWebhook: vi.fn().mockResolvedValue({ ok: true }),
    };
    const app = buildWebhookApp({ redis, stripe });

    const hugeId = 'evt_' + 'x'.repeat(10000);
    const res = await app.request('http://billing.local/stripe', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_huge' },
      body: JSON.stringify({ id: hugeId }),
    });

    // Should process normally (or dedup), not crash
    expect(res.status).toBe(200);
  });
});