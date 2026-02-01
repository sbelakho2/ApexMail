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
    const result = await ctx.stripe.handleWebhook(rawBody, signature);

    if (!result.ok) {
      console.error('Stripe webhook error:', result.error);
      return c.json({ error: result.error.message }, 400);
    }

    return c.json({ received: true });
  });

  // Paddle webhooks (fallback payment processor)
  router.post('/paddle', async (c) => {
    const body = await c.req.json();

    // Verify Paddle signature
    const signature = c.req.header('paddle-signature');
    if (!signature) {
      return c.json({ error: 'Missing paddle-signature header' }, 400);
    }

    // Handle Paddle events
    const eventType = body.event_type;

    switch (eventType) {
      case 'subscription.activated':
        await handlePaddleSubscriptionActivated(ctx, body);
        break;
      case 'subscription.updated':
        await handlePaddleSubscriptionUpdated(ctx, body);
        break;
      case 'subscription.canceled':
        await handlePaddleSubscriptionCanceled(ctx, body);
        break;
      case 'transaction.completed':
        await handlePaddleTransactionCompleted(ctx, body);
        break;
      case 'transaction.payment_failed':
        await handlePaddlePaymentFailed(ctx, body);
        break;
      default:
        console.log(`Unhandled Paddle event: ${eventType}`);
    }

    return c.json({ received: true });
  });

  return router;
}

async function handlePaddleSubscriptionActivated(
  ctx: BillingContext,
  body: PaddleWebhookPayload
): Promise<void> {
  const tenantId = body.data.custom_data?.tenant_id;
  if (!tenantId) {
    console.error('No tenant_id in Paddle subscription');
    return;
  }

  const subscriptionData = {
    paddleSubscriptionId: body.data.id,
    paddleCustomerId: body.data.customer_id,
    status: 'active' as const,
    currentPeriodStart: new Date(body.data.current_billing_period.starts_at),
    currentPeriodEnd: new Date(body.data.current_billing_period.ends_at),
    priceId: body.data.items[0]?.price?.id,
  };

  await ctx.db.query(
    `INSERT INTO paddle_subscriptions (
      tenant_id, paddle_subscription_id, paddle_customer_id, status,
      current_period_start, current_period_end, price_id, created_at, updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
    ON CONFLICT (tenant_id) DO UPDATE SET
      paddle_subscription_id = $2,
      paddle_customer_id = $3,
      status = $4,
      current_period_start = $5,
      current_period_end = $6,
      price_id = $7,
      updated_at = NOW()`,
    [
      tenantId,
      subscriptionData.paddleSubscriptionId,
      subscriptionData.paddleCustomerId,
      subscriptionData.status,
      subscriptionData.currentPeriodStart,
      subscriptionData.currentPeriodEnd,
      subscriptionData.priceId,
    ]
  );
}

async function handlePaddleSubscriptionUpdated(
  ctx: BillingContext,
  body: PaddleWebhookPayload
): Promise<void> {
  const subscriptionId = body.data.id;

  await ctx.db.query(
    `UPDATE paddle_subscriptions SET
      status = $2,
      current_period_start = $3,
      current_period_end = $4,
      price_id = $5,
      updated_at = NOW()
    WHERE paddle_subscription_id = $1`,
    [
      subscriptionId,
      body.data.status,
      new Date(body.data.current_billing_period.starts_at),
      new Date(body.data.current_billing_period.ends_at),
      body.data.items[0]?.price?.id,
    ]
  );
}

async function handlePaddleSubscriptionCanceled(
  ctx: BillingContext,
  body: PaddleWebhookPayload
): Promise<void> {
  const subscriptionId = body.data.id;

  await ctx.db.query(
    `UPDATE paddle_subscriptions SET
      status = 'canceled',
      canceled_at = NOW(),
      updated_at = NOW()
    WHERE paddle_subscription_id = $1`,
    [subscriptionId]
  );
}

async function handlePaddleTransactionCompleted(
  ctx: BillingContext,
  body: PaddleWebhookPayload
): Promise<void> {
  const transaction = body.data;
  const tenantId = transaction.custom_data?.tenant_id;

  if (!tenantId) return;

  await ctx.db.query(
    `INSERT INTO paddle_transactions (
      tenant_id, paddle_transaction_id, amount, currency,
      status, created_at
    ) VALUES ($1, $2, $3, $4, $5, NOW())
    ON CONFLICT (paddle_transaction_id) DO NOTHING`,
    [
      tenantId,
      transaction.id,
      parseInt(transaction.details.totals.total, 10),
      transaction.currency_code,
      'completed',
    ]
  );
}

async function handlePaddlePaymentFailed(
  ctx: BillingContext,
  body: PaddleWebhookPayload
): Promise<void> {
  const transaction = body.data;
  const tenantId = transaction.custom_data?.tenant_id;

  if (!tenantId) return;

  // Start dunning process
  await ctx.dunning.startDunning(tenantId, {
    amount: parseInt(transaction.details.totals.total, 10),
    currency: transaction.currency_code,
    failureReason: transaction.payments?.[0]?.error_code ?? 'unknown',
    processor: 'paddle',
  });
}

interface PaddleWebhookPayload {
  event_type: string;
  data: {
    id: string;
    customer_id: string;
    status: string;
    custom_data?: {
      tenant_id?: string;
    };
    current_billing_period: {
      starts_at: string;
      ends_at: string;
    };
    items: Array<{
      price?: {
        id: string;
      };
    }>;
    details: {
      totals: {
        total: string;
      };
    };
    currency_code: string;
    payments?: Array<{
      error_code?: string;
    }>;
  };
}
