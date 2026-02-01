/**
 * Stripe Integration Service
 * Handles all Stripe operations with idempotency and webhook processing
 */

import Stripe from 'stripe';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import { getStripe } from '../lib/stripe-client.js';
import { getConfig } from '../config.js';

const logger = createLogger('stripe-integration');

export interface StripeCustomer {
  id: string;
  tenantId: string;
  stripeCustomerId: string;
  email: string;
  name: string;
  defaultPaymentMethodId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface StripeSubscription {
  id: string;
  tenantId: string;
  stripeSubscriptionId: string;
  stripeCustomerId: string;
  stripePriceId: string;
  status: SubscriptionStatus;
  billingInterval: 'monthly' | 'yearly';
  billingCycleStart: Date;
  billingCycleEnd: Date;
  cancelAtPeriodEnd: boolean;
  canceledAt: Date | null;
  trialEnd: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type SubscriptionStatus = 
  | 'active'
  | 'past_due'
  | 'unpaid'
  | 'canceled'
  | 'incomplete'
  | 'incomplete_expired'
  | 'trialing'
  | 'paused';

/**
 * Stripe integration service
 */
export class StripeService {
  private readonly stripe: Stripe;

  constructor(private readonly db: DatabasePool) {
    this.stripe = getStripe();
  }

  /**
   * Create or get Stripe customer for tenant
   */
  async getOrCreateCustomer(
    tenantId: string,
    email: string,
    name: string,
    metadata?: Record<string, string>
  ): Promise<Result<StripeCustomer, Error>> {
    // Check if customer already exists
    const existingResult = await this.db.query<{
      id: string;
      tenant_id: string;
      stripe_customer_id: string;
      email: string;
      name: string;
      default_payment_method_id: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM stripe_customers WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!existingResult.ok) return Result.err(existingResult.error);

    if (existingResult.value.rows[0]) {
      const row = existingResult.value.rows[0];
      return Result.ok({
        id: row.id,
        tenantId: row.tenant_id,
        stripeCustomerId: row.stripe_customer_id,
        email: row.email,
        name: row.name,
        defaultPaymentMethodId: row.default_payment_method_id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      });
    }

    // Create Stripe customer
    try {
      const stripeCustomer = await this.stripe.customers.create({
        email,
        name,
        metadata: {
          tenant_id: tenantId,
          ...metadata,
        },
      });

      // Store in database
      const insertResult = await this.db.query<{
        id: string;
        created_at: Date;
        updated_at: Date;
      }>(
        `INSERT INTO stripe_customers (
          id, tenant_id, stripe_customer_id, email, name, created_at, updated_at
        )
        VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW())
        RETURNING id, created_at, updated_at`,
        [tenantId, stripeCustomer.id, email, name]
      );

      if (!insertResult.ok) return Result.err(insertResult.error);

      const row = insertResult.value.rows[0]!;
      return Result.ok({
        id: row.id,
        tenantId,
        stripeCustomerId: stripeCustomer.id,
        email,
        name,
        defaultPaymentMethodId: null,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      });
    } catch (error) {
      logger.error({ error, tenantId }, 'Failed to create Stripe customer');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Create checkout session for subscription
   */
  async createCheckoutSession(
    tenantId: string,
    priceId: string,
    successUrl: string,
    cancelUrl: string
  ): Promise<Result<{ sessionId: string; url: string }, Error>> {
    // Get or create customer
    const tenantResult = await this.db.query<{
      name: string;
      settings: string;
    }>(
      `SELECT name, settings FROM tenants WHERE id = $1`,
      [tenantId]
    );

    if (!tenantResult.ok) return Result.err(tenantResult.error);

    const tenant = tenantResult.value.rows[0];
    if (!tenant) return Result.err(new Error('Tenant not found'));

    const settings = JSON.parse(tenant.settings || '{}');
    const email = settings.billingEmail || settings.defaultFromEmail;

    if (!email) {
      return Result.err(new Error('No billing email configured'));
    }

    const customerResult = await this.getOrCreateCustomer(tenantId, email, tenant.name);
    if (!customerResult.ok) return Result.err(customerResult.error);

    try {
      const session = await this.stripe.checkout.sessions.create({
        customer: customerResult.value.stripeCustomerId,
        payment_method_types: ['card'],
        line_items: [
          {
            price: priceId,
            quantity: 1,
          },
        ],
        mode: 'subscription',
        success_url: successUrl,
        cancel_url: cancelUrl,
        subscription_data: {
          metadata: {
            tenant_id: tenantId,
          },
        },
        allow_promotion_codes: true,
        billing_address_collection: 'required',
        tax_id_collection: {
          enabled: true,
        },
      });

      return Result.ok({
        sessionId: session.id,
        url: session.url!,
      });
    } catch (error) {
      logger.error({ error, tenantId, priceId }, 'Failed to create checkout session');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Create customer portal session for self-service
   */
  async createPortalSession(
    tenantId: string,
    returnUrl: string
  ): Promise<Result<{ url: string }, Error>> {
    const customerResult = await this.db.query<{
      stripe_customer_id: string;
    }>(
      `SELECT stripe_customer_id FROM stripe_customers WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!customerResult.ok) return Result.err(customerResult.error);

    const row = customerResult.value.rows[0];
    if (!row) return Result.err(new Error('No Stripe customer found'));

    try {
      const session = await this.stripe.billingPortal.sessions.create({
        customer: row.stripe_customer_id,
        return_url: returnUrl,
      });

      return Result.ok({ url: session.url });
    } catch (error) {
      logger.error({ error, tenantId }, 'Failed to create portal session');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Process Stripe webhook event with idempotency
   */
  async processWebhook(
    payload: string | Buffer,
    signature: string
  ): Promise<Result<{ eventType: string; processed: boolean }, Error>> {
    const config = getConfig();

    let event: Stripe.Event;
    try {
      event = this.stripe.webhooks.constructEvent(
        payload,
        signature,
        config.STRIPE_WEBHOOK_SECRET
      );
    } catch (error) {
      logger.warn({ error }, 'Invalid webhook signature');
      return Result.err(new Error('Invalid webhook signature'));
    }

    // Check idempotency
    const idempotencyResult = await this.db.query<{ id: string }>(
      `SELECT id FROM stripe_webhook_events WHERE stripe_event_id = $1`,
      [event.id]
    );

    if (!idempotencyResult.ok) return Result.err(idempotencyResult.error);

    if (idempotencyResult.value.rows.length > 0) {
      logger.info({ eventId: event.id }, 'Duplicate webhook event, skipping');
      return Result.ok({ eventType: event.type, processed: false });
    }

    // Record event
    await this.db.query(
      `INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, processed_at, created_at)
       VALUES (gen_random_uuid(), $1, $2, NOW(), NOW())`,
      [event.id, event.type]
    );

    // Process event
    try {
      await this.handleStripeEvent(event);
      return Result.ok({ eventType: event.type, processed: true });
    } catch (error) {
      logger.error({ error, eventType: event.type }, 'Failed to process webhook');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Handle specific Stripe events
   */
  private async handleStripeEvent(event: Stripe.Event): Promise<void> {
    switch (event.type) {
      case 'checkout.session.completed':
        await this.handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
        break;

      case 'customer.subscription.created':
      case 'customer.subscription.updated':
        await this.handleSubscriptionChange(event.data.object as Stripe.Subscription);
        break;

      case 'customer.subscription.deleted':
        await this.handleSubscriptionDeleted(event.data.object as Stripe.Subscription);
        break;

      case 'invoice.paid':
        await this.handleInvoicePaid(event.data.object as Stripe.Invoice);
        break;

      case 'invoice.payment_failed':
        await this.handlePaymentFailed(event.data.object as Stripe.Invoice);
        break;

      case 'customer.subscription.trial_will_end':
        await this.handleTrialEnding(event.data.object as Stripe.Subscription);
        break;

      default:
        logger.debug({ eventType: event.type }, 'Unhandled event type');
    }
  }

  private async handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
    const tenantId = session.metadata?.tenant_id;
    if (!tenantId) {
      logger.warn({ sessionId: session.id }, 'No tenant_id in checkout session');
      return;
    }

    logger.info({ tenantId, sessionId: session.id }, 'Checkout completed');

    // Update tenant billing status
    await this.db.query(
      `UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1`,
      [tenantId]
    );
  }

  private async handleSubscriptionChange(subscription: Stripe.Subscription): Promise<void> {
    const tenantId = subscription.metadata?.tenant_id;
    if (!tenantId) {
      logger.warn({ subscriptionId: subscription.id }, 'No tenant_id in subscription');
      return;
    }

    const priceId = subscription.items.data[0]?.price.id;
    const interval = subscription.items.data[0]?.price.recurring?.interval;

    // Upsert subscription record
    await this.db.query(
      `INSERT INTO subscriptions (
        id, tenant_id, stripe_subscription_id, stripe_customer_id, stripe_price_id,
        status, billing_interval, billing_cycle_start, billing_cycle_end,
        cancel_at_period_end, canceled_at, trial_end, created_at, updated_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, $3, $4, $5, $6, 
        to_timestamp($7), to_timestamp($8), $9, $10, $11, NOW(), NOW()
      )
      ON CONFLICT (stripe_subscription_id) DO UPDATE SET
        status = $5,
        billing_interval = $6,
        billing_cycle_start = to_timestamp($7),
        billing_cycle_end = to_timestamp($8),
        cancel_at_period_end = $9,
        canceled_at = $10,
        trial_end = $11,
        updated_at = NOW()`,
      [
        tenantId,
        subscription.id,
        subscription.customer as string,
        priceId,
        subscription.status,
        interval === 'year' ? 'yearly' : 'monthly',
        subscription.current_period_start,
        subscription.current_period_end,
        subscription.cancel_at_period_end,
        subscription.canceled_at ? new Date(subscription.canceled_at * 1000) : null,
        subscription.trial_end ? new Date(subscription.trial_end * 1000) : null,
      ]
    );

    // Update tenant plan based on price
    const planResult = await this.db.query<{ name: string }>(
      `SELECT name FROM plans WHERE stripe_price_id_monthly = $1 OR stripe_price_id_yearly = $1`,
      [priceId]
    );

    if (planResult.ok && planResult.value.rows[0]) {
      await this.db.query(
        `UPDATE tenants SET plan = $1, updated_at = NOW() WHERE id = $2`,
        [planResult.value.rows[0].name, tenantId]
      );
    }

    logger.info({ tenantId, subscriptionId: subscription.id, status: subscription.status }, 'Subscription updated');
  }

  private async handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
    const tenantId = subscription.metadata?.tenant_id;
    if (!tenantId) return;

    await this.db.query(
      `UPDATE subscriptions SET status = 'canceled', updated_at = NOW() WHERE stripe_subscription_id = $1`,
      [subscription.id]
    );

    // Downgrade to free plan
    await this.db.query(
      `UPDATE tenants SET plan = 'free', updated_at = NOW() WHERE id = $1`,
      [tenantId]
    );

    logger.info({ tenantId, subscriptionId: subscription.id }, 'Subscription canceled');
  }

  private async handleInvoicePaid(invoice: Stripe.Invoice): Promise<void> {
    const tenantId = invoice.subscription_details?.metadata?.tenant_id;
    if (!tenantId) return;

    // Sync invoice to our database
    await this.db.query(
      `UPDATE invoices SET status = 'paid', paid_at = NOW(), updated_at = NOW()
       WHERE stripe_invoice_id = $1`,
      [invoice.id]
    );

    logger.info({ tenantId, invoiceId: invoice.id }, 'Invoice paid');
  }

  private async handlePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
    const tenantId = invoice.subscription_details?.metadata?.tenant_id;
    if (!tenantId) return;

    // Queue dunning notification
    await this.db.query(
      `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
       VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())`,
      [tenantId, JSON.stringify({
        invoiceId: invoice.id,
        amount: invoice.amount_due,
        attemptCount: invoice.attempt_count,
      })]
    );

    logger.warn({ tenantId, invoiceId: invoice.id, attemptCount: invoice.attempt_count }, 'Payment failed');
  }

  private async handleTrialEnding(subscription: Stripe.Subscription): Promise<void> {
    const tenantId = subscription.metadata?.tenant_id;
    if (!tenantId) return;

    // Queue trial ending notification
    await this.db.query(
      `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
       VALUES (gen_random_uuid(), $1, 'trial_ending', $2, 'pending', NOW())`,
      [tenantId, JSON.stringify({
        subscriptionId: subscription.id,
        trialEnd: subscription.trial_end,
      })]
    );

    logger.info({ tenantId, subscriptionId: subscription.id }, 'Trial ending soon');
  }

  /**
   * Create refund
   */
  async createRefund(
    paymentIntentId: string,
    amount?: number,
    reason?: string
  ): Promise<Result<Stripe.Refund, Error>> {
    try {
      const refund = await this.stripe.refunds.create({
        payment_intent: paymentIntentId,
        amount,
        reason: reason as Stripe.RefundCreateParams.Reason,
      });

      return Result.ok(refund);
    } catch (error) {
      logger.error({ error, paymentIntentId }, 'Failed to create refund');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Get subscription status
   */
  async getSubscription(tenantId: string): Promise<Result<StripeSubscription | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      stripe_subscription_id: string;
      stripe_customer_id: string;
      stripe_price_id: string;
      status: SubscriptionStatus;
      billing_interval: 'monthly' | 'yearly';
      billing_cycle_start: Date;
      billing_cycle_end: Date;
      cancel_at_period_end: boolean;
      canceled_at: Date | null;
      trial_end: Date | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM subscriptions WHERE tenant_id = $1 AND status != 'canceled' ORDER BY created_at DESC LIMIT 1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok({
      id: row.id,
      tenantId: row.tenant_id,
      stripeSubscriptionId: row.stripe_subscription_id,
      stripeCustomerId: row.stripe_customer_id,
      stripePriceId: row.stripe_price_id,
      status: row.status,
      billingInterval: row.billing_interval,
      billingCycleStart: row.billing_cycle_start,
      billingCycleEnd: row.billing_cycle_end,
      cancelAtPeriodEnd: row.cancel_at_period_end,
      canceledAt: row.canceled_at,
      trialEnd: row.trial_end,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }
}
