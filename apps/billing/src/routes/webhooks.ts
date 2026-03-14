/**
 * Webhooks Routes - Stripe webhook handlers
 */

import { Hono } from 'hono';
import type { BillingEnv, BillingContext } from '../app.js';
import { logger } from '../lib/logger.js';

export function webhooksRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();
  const DEADLETTER_KEY = 'stripe:deadletter';
  const MAX_DEADLETTER_EVENTS = 1000;

  // Stripe webhooks
  router.post('/stripe', async (c) => {
    const signature = c.req.header('stripe-signature');

    if (!signature) {
      await ctx.redis.lpush(DEADLETTER_KEY, JSON.stringify({
        reason: 'missing_signature',
        occurredAt: new Date().toISOString(),
      }));
      await ctx.redis.ltrim(DEADLETTER_KEY, 0, MAX_DEADLETTER_EVENTS - 1);
      return c.json({ error: 'Missing stripe-signature header' }, 400);
    }

    const rawBody = await c.req.text();
    
    // SEC-006 FIX: Add event ID deduplication to prevent replay attacks
    // Extract event ID from raw body before verification (safe to parse for ID only)
    let eventId: string | undefined;
    try {
      const parsed = JSON.parse(rawBody) as { id?: string };
      eventId = parsed.id;
    } catch (error) {
      await ctx.redis.lpush(DEADLETTER_KEY, JSON.stringify({
        reason: 'invalid_json_payload',
        error: String(error),
        occurredAt: new Date().toISOString(),
        payloadPreview: rawBody.slice(0, 1024),
      }));
      await ctx.redis.ltrim(DEADLETTER_KEY, 0, MAX_DEADLETTER_EVENTS - 1);
      return c.json({ error: 'Invalid JSON payload' }, 400);
    }
    
    if (!eventId) {
      await ctx.redis.lpush(DEADLETTER_KEY, JSON.stringify({
        reason: 'missing_event_id',
        occurredAt: new Date().toISOString(),
        payloadPreview: rawBody.slice(0, 1024),
      }));
      await ctx.redis.ltrim(DEADLETTER_KEY, 0, MAX_DEADLETTER_EVENTS - 1);
      return c.json({ error: 'Missing event ID' }, 400);
    }
    
    // Check for duplicate event - 24 hour deduplication window
    const dedupKey = `stripe:event:${eventId}`;
    const wasSet = await ctx.redis.set(dedupKey, '1', 'EX', 86400, 'NX');
    
    if (!wasSet) {
      // Event already processed - return simple response (Stripe ignores body anyway)
      return c.json({ received: true });
    }
    
    const result = await ctx.stripe.processWebhook(rawBody, signature);

    if (!result.ok) {
      await ctx.redis.lpush(DEADLETTER_KEY, JSON.stringify({
        reason: 'processing_failed',
        occurredAt: new Date().toISOString(),
        eventId,
        error: result.error instanceof Error ? result.error.message : String(result.error),
      }));
      await ctx.redis.ltrim(DEADLETTER_KEY, 0, MAX_DEADLETTER_EVENTS - 1);
      // On processing failure, remove dedup key to allow retry
      await ctx.redis.del(dedupKey);
      logger.error('Stripe webhook error', { error: result.error instanceof Error ? result.error.message : String(result.error) });
      return c.json({ error: 'Webhook processing failed' }, 400);
    }

    return c.json({ received: true });
  });

  return router;
}
