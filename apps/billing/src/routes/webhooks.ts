/**
 * Webhooks Routes - Stripe webhook handlers
 */

import { Hono } from 'hono';
import type { BillingEnv, BillingContext } from '../app.js';
import { logger } from '../lib/logger.js';

const DEADLETTER_EVENT_PREFIX = 'stripe:deadletter:event:';
const DEADLETTER_INDEX_KEY = 'stripe:deadletter:index';
const DEADLETTER_RETENTION_SECONDS = 35 * 24 * 60 * 60;
const DEADLETTER_RETENTION_MS = DEADLETTER_RETENTION_SECONDS * 1000;

type DeadletterEntry = {
  reason: string;
  occurredAt?: string;
  eventId?: string;
  error?: string;
  payloadLength?: number;
};

async function recordDeadletter(ctx: BillingContext, entry: DeadletterEntry): Promise<void> {
  const now = Date.now();
  const occurredAt = entry.occurredAt ?? new Date(now).toISOString();
  const eventId = entry.eventId?.trim();
  const eventIdPart = eventId && eventId.length > 0
    ? eventId.replace(/[^A-Za-z0-9_-]/g, '_')
    : 'unknown';
  const eventKey = `${DEADLETTER_EVENT_PREFIX}${eventIdPart}:${now}`;

  try {
    const pipeline = ctx.redis.pipeline();
    pipeline.setex(eventKey, DEADLETTER_RETENTION_SECONDS, JSON.stringify({ ...entry, occurredAt }));
    pipeline.zadd(DEADLETTER_INDEX_KEY, now, eventKey);
    pipeline.zremrangebyscore(DEADLETTER_INDEX_KEY, 0, now - DEADLETTER_RETENTION_MS);
    pipeline.expire(DEADLETTER_INDEX_KEY, DEADLETTER_RETENTION_SECONDS);
    await pipeline.exec();
  } catch (error) {
    logger.error('Failed to record Stripe dead letter', {
      reason: entry.reason,
      eventId: entry.eventId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

export function webhooksRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  // Stripe webhooks
  router.post('/stripe', async (c) => {
    const signature = c.req.header('stripe-signature');

    if (!signature) {
      await recordDeadletter(ctx, {
        reason: 'missing_signature',
      });
      return c.json({ error: 'Missing stripe-signature header' }, 400);
    }

    const rawBody = await c.req.text();

    // Parse only the event id to validate payload shape before signature verification.
    let eventId: string | undefined;
    try {
      const parsed = JSON.parse(rawBody) as { id?: string };
      eventId = typeof parsed.id === 'string' ? parsed.id : undefined;
    } catch (error) {
      await recordDeadletter(ctx, {
        reason: 'invalid_json_payload',
        error: String(error),
        payloadLength: rawBody.length,
      });
      return c.json({ error: 'Invalid JSON payload' }, 400);
    }

    if (!eventId || eventId.trim().length === 0) {
      await recordDeadletter(ctx, {
        reason: 'missing_event_id',
        payloadLength: rawBody.length,
      });
      return c.json({ error: 'Missing event ID' }, 400);
    }

    const result = await ctx.stripe.processWebhook(rawBody, signature);

    if (!result.ok) {
      await recordDeadletter(ctx, {
        reason: 'processing_failed',
        eventId,
        error: result.error instanceof Error ? result.error.message : String(result.error),
      });
      logger.error('Stripe webhook error', { error: result.error instanceof Error ? result.error.message : String(result.error) });
      return c.json({ error: 'Webhook processing failed' }, 400);
    }

    return c.json({ received: true });
  });

  return router;
}
