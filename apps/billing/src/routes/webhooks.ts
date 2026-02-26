/**
 * Webhooks Routes - Stripe webhook handlers
 */

import { Hono } from 'hono';
import type { BillingEnv, BillingContext } from '../app.js';

export function webhooksRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  // Stripe webhooks
  router.post('/stripe', async (c) => {
    const signature = c.req.header('stripe-signature');

    if (!signature) {
      return c.json({ error: 'Missing stripe-signature header' }, 400);
    }

    const rawBody = await c.req.text();
    
    // SEC-006 FIX: Add event ID deduplication to prevent replay attacks
    // Extract event ID from raw body before verification (safe to parse for ID only)
    let eventId: string | undefined;
    try {
      const parsed = JSON.parse(rawBody) as { id?: string };
      eventId = parsed.id;
    } catch {
      return c.json({ error: 'Invalid JSON payload' }, 400);
    }
    
    if (!eventId) {
      return c.json({ error: 'Missing event ID' }, 400);
    }
    
    // Check for duplicate event - 24 hour deduplication window
    const dedupKey = `stripe:event:${eventId}`;
    const wasSet = await ctx.redis.set(dedupKey, '1', 'EX', 86400, 'NX');
    
    if (!wasSet) {
      // Event already processed - return success (idempotent)
      return c.json({ received: true, deduplicated: true });
    }
    
    const result = await ctx.stripe.processWebhook(rawBody, signature);

    if (!result.ok) {
      // On processing failure, remove dedup key to allow retry
      await ctx.redis.del(dedupKey);
      console.error('Stripe webhook error:', result.error);
      return c.json({ error: 'Webhook processing failed' }, 400);
    }

    return c.json({ received: true });
  });

  return router;
}
