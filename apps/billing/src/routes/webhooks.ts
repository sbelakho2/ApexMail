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
    const result = await ctx.stripe.processWebhook(rawBody, signature);

    if (!result.ok) {
      console.error('Stripe webhook error:', result.error);
      return c.json({ error: result.error.message }, 400);
    }

    return c.json({ received: true });
  });

  return router;
}
