/**
 * Stripe Integration Service
 * Handles all Stripe operations with idempotency and webhook processing
 * 
 * SEC-016: Includes circuit breaker pattern to prevent cascading failures
 * when Stripe API is unavailable or slow.
 */

import Stripe from 'stripe';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import type { DunningService } from './dunning.js';
import { StripeCircuitBreaker } from './stripe-circuit-breaker.js';
import { getStripe } from '../lib/stripe-client.js';
import { config, getConfig } from '../config.js';
import { STRIPE_WEBHOOK_TOLERANCE_SECONDS, MS_PER_SECOND } from '../lib/constants.js';

const logger = createLogger();

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

type StripeCustomerRow = {
  id: string;
  tenant_id: string;
  stripe_customer_id: string;
  email: string;
  name: string;
  default_payment_method_id: string | null;
  created_at: Date;
  updated_at: Date;
};

type StripeSubscriptionRow = {
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
};

/**
 * Stripe integration service
 */
export class StripeService {
  private readonly stripe: Stripe;
  private readonly circuitBreaker: StripeCircuitBreaker;

  constructor(
    private readonly db: DatabasePool,
    private readonly dunning?: DunningService,
  ) {
    this.stripe = getStripe();
    this.circuitBreaker = new StripeCircuitBreaker();
  }

  private async executeStripeCall<T>(
    operation: string,
    metadata: Record<string, unknown>,
    fn: () => Promise<T>
  ): Promise<T> {
    try {
      return await this.circuitBreaker.execute(fn);
    } catch (error) {
      logger.error(`Stripe operation failed: ${operation}`, {
        ...metadata,
        error: error instanceof Error ? error.message : String(error),
        circuitState: this.circuitBreaker.getState(),
      });
      throw error;
    }
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
    const existingResult = await this.db.query<StripeCustomerRow>(
      `SELECT id, tenant_id, stripe_customer_id, email, name,
              default_payment_method_id, created_at, updated_at
       FROM stripe_customers WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!existingResult.ok) return Result.err(existingResult.error);

    if (existingResult.value.rows[0]) {
      const row = existingResult.value.rows[0];
      return Result.ok(this.mapStripeCustomer(row));
    }

    // Create Stripe customer
    try {
      const stripeCustomer = await this.executeStripeCall(
        'customers.create',
        { tenantId, email },
        () => this.stripe.customers.create({
          email,
          name,
          metadata: {
            tenant_id: tenantId,
            ...metadata,
          },
        })
      );

      // Store in database using ON CONFLICT to handle race conditions
      // CRITICAL: Another request may have created the customer between our SELECT and INSERT
      const insertResult = await this.db.query<{
        id: string;
        stripe_customer_id: string;
        created_at: Date;
        updated_at: Date;
      }>(
        `INSERT INTO stripe_customers (
          id, tenant_id, stripe_customer_id, email, name, created_at, updated_at
        )
        VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET updated_at = NOW()
        RETURNING id, stripe_customer_id, created_at, updated_at`,
        [tenantId, stripeCustomer.id, email, name]
      );

      if (!insertResult.ok) return Result.err(insertResult.error);

      const row = insertResult.value.rows[0];
      if (!row) {
        return Result.err(new Error('INSERT RETURNING produced no rows'));
      };
      
      // If we hit ON CONFLICT, the returned stripe_customer_id is the existing one
      // We should delete the Stripe customer we just created if it was a duplicate
      if (row.stripe_customer_id !== stripeCustomer.id) {
        // Another request won the race - delete the duplicate Stripe customer
        // Log detailed error information for debugging and billing reconciliation
        try {
          await this.executeStripeCall(
            'customers.delete-duplicate',
            { tenantId, duplicateCustomerId: stripeCustomer.id },
            () => this.stripe.customers.del(stripeCustomer.id)
          );
          logger.info('Deleted duplicate Stripe customer', { 
            duplicateId: stripeCustomer.id, 
            existingId: row.stripe_customer_id,
            tenantId,
            email 
          });
        } catch (deleteError) {
          // Do NOT swallow this error - log with full context for billing ops to investigate
          // Orphaned Stripe customers can cause billing issues and need manual cleanup
          logger.error('CRITICAL: Failed to delete duplicate Stripe customer - manual cleanup required', { 
            error: deleteError instanceof Error ? deleteError.message : String(deleteError),
            errorStack: deleteError instanceof Error ? deleteError.stack : undefined,
            duplicateCustomerId: stripeCustomer.id, 
            existingCustomerId: row.stripe_customer_id,
            tenantId,
            email,
            action: 'MANUAL_STRIPE_CUSTOMER_CLEANUP_REQUIRED'
          });
          // Record orphaned customer for later cleanup
          await this.db.query(
            `INSERT INTO stripe_orphaned_customers (id, stripe_customer_id, tenant_id, reason, created_at)
             VALUES (gen_random_uuid(), $1, $2, 'race_condition_duplicate', NOW())
             ON CONFLICT (stripe_customer_id) DO NOTHING`,
            [stripeCustomer.id, tenantId]
          ).catch(dbErr => {
            logger.error('Failed to record orphaned customer', { error: dbErr, customerId: stripeCustomer.id });
          });
        }
      }
      
      return Result.ok({
        id: row.id,
        tenantId,
        stripeCustomerId: row.stripe_customer_id,
        email,
        name,
        defaultPaymentMethodId: null,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      });
    } catch (error) {
      logger.error('Failed to create Stripe customer', { error, tenantId });
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

    let settings: { billingEmail?: string; defaultFromEmail?: string } = {};
    try {
      settings = JSON.parse(tenant.settings || '{}');
    } catch (error) {
      logger.warn('Failed to parse tenant settings for Stripe sync', { tenantId, error: String(error) });
      settings = {};
    }
    const email = settings.billingEmail || settings.defaultFromEmail;

    if (!email) {
      return Result.err(new Error('No billing email configured'));
    }

    const customerResult = await this.getOrCreateCustomer(tenantId, email, tenant.name);
    if (!customerResult.ok) return Result.err(customerResult.error);

    try {
      const session = await this.executeStripeCall(
        'checkout.sessions.create',
        { tenantId, priceId },
        () => this.stripe.checkout.sessions.create({
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
        })
      );

      // SECURITY FIX: Validate session URL exists before returning
      if (!session.url) {
        logger.error('Stripe checkout session created without URL', { sessionId: session.id, tenantId });
        return Result.err(new Error('Stripe returned a session without a URL'));
      }

      return Result.ok({
        sessionId: session.id,
        url: session.url,
      });
    } catch (error) {
      logger.error('Failed to create checkout session', { error, tenantId, priceId });
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
      const session = await this.executeStripeCall(
        'billingPortal.sessions.create',
        { tenantId },
        () => this.stripe.billingPortal.sessions.create({
          customer: row.stripe_customer_id,
          return_url: returnUrl,
        })
      );

      return Result.ok({ url: session.url });
    } catch (error) {
      logger.error('Failed to create portal session', { error, tenantId });
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Process Stripe webhook event with idempotency
   * SECURITY FIX: Record event AFTER successful processing to allow retries on failures
   */
  async processWebhook(
    payload: string | Buffer,
    signature: string
  ): Promise<Result<{ eventType: string; processed: boolean }, Error>> {
    const config = getConfig();

    let event: Stripe.Event;
    try {
      /**
       * G-226: Replay protection — constructEvent verifies both signature
       * and timestamp. The tolerance parameter (in seconds) rejects events
       * older than 5 minutes, preventing replay attacks where an attacker
       * captures and re-sends a valid webhook payload after the fact.
       */
      const WEBHOOK_TOLERANCE_SECONDS = STRIPE_WEBHOOK_TOLERANCE_SECONDS; // 5 minutes
      event = this.stripe.webhooks.constructEvent(
        payload,
        signature,
        config.STRIPE_WEBHOOK_SECRET,
        WEBHOOK_TOLERANCE_SECONDS
      );
    } catch (error) {
      logger.warn('Invalid webhook signature or replayed event', { error });
      return Result.err(new Error('Invalid webhook signature'));
    }

    // Check idempotency - only skip if successfully processed (status = 'processed')
    const idempotencyResult = await this.db.query<{ id: string; status: string }>(
      `SELECT id, status FROM stripe_webhook_events WHERE stripe_event_id = $1`,
      [event.id]
    );

    if (!idempotencyResult.ok) return Result.err(idempotencyResult.error);

    const existingEvent = idempotencyResult.value.rows[0];
    if (existingEvent) {
      if (existingEvent.status === 'processed') {
        logger.info('Duplicate webhook event already processed, skipping', { eventId: event.id });
        return Result.ok({ eventType: event.type, processed: false });
      }
      // If status is 'failed' or 'pending', we should retry
      logger.info('Retrying previously failed webhook event', { eventId: event.id, previousStatus: existingEvent.status });
    }

    // CRITICAL FIX: Insert event as 'pending' first (or update if retrying)
    const upsertResult = await this.db.query(
      `INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status, created_at, updated_at)
       VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
       ON CONFLICT (stripe_event_id) DO UPDATE SET status = 'pending', updated_at = NOW()
       RETURNING id`,
      [event.id, event.type]
    );

    if (!upsertResult.ok) return Result.err(upsertResult.error);

    // Process event
    try {
      await this.handleStripeEvent(event);
      
      // CRITICAL: Only mark as processed AFTER successful handling
      await this.db.query(
        `UPDATE stripe_webhook_events 
         SET status = 'processed', processed_at = NOW(), updated_at = NOW() 
         WHERE stripe_event_id = $1`,
        [event.id]
      );
      
      return Result.ok({ eventType: event.type, processed: true });
    } catch (error) {
      // Mark as failed so Stripe can retry
      await this.db.query(
        `UPDATE stripe_webhook_events 
         SET status = 'failed', error = $2, updated_at = NOW() 
         WHERE stripe_event_id = $1`,
        [event.id, error instanceof Error ? error.message : String(error)]
      );
      
      logger.error('Failed to process webhook', { error, eventType: event.type });
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
        logger.debug('Unhandled event type', { eventType: event.type });
    }
  }

  private async handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
    const tenantId = session.metadata?.tenant_id;
    if (!tenantId) {
      logger.warn('No tenant_id in checkout session', { sessionId: session.id });
      return;
    }

    logger.info('Checkout completed', { tenantId, sessionId: session.id });

    // Update tenant billing status
    await this.db.query(
      `UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1`,
      [tenantId]
    );
  }

  /**
   * Valid subscription status transitions.
   * Prevents invalid jumps (e.g. active → expired directly) by only
   * allowing transitions that match Stripe's subscription lifecycle.
   */
  private static readonly VALID_STATUS_TRANSITIONS: Record<string, SubscriptionStatus[]> = {
    incomplete:          ['active', 'incomplete_expired'],
    incomplete_expired:  [],
    trialing:            ['active', 'past_due', 'canceled', 'unpaid', 'paused'],
    active:              ['past_due', 'canceled', 'unpaid', 'paused'],
    past_due:            ['active', 'canceled', 'unpaid'],
    unpaid:              ['active', 'canceled'],
    canceled:            [],
    paused:              ['active', 'canceled'],
  };

  private async handleSubscriptionChange(subscription: Stripe.Subscription): Promise<void> {
    const tenantId = subscription.metadata?.tenant_id;
    if (!tenantId) {
      logger.warn('No tenant_id in subscription', { subscriptionId: subscription.id });
      return;
    }

    // E-184: Validate status transition before applying
    const newStatus = subscription.status as SubscriptionStatus;
    const currentResult = await this.db.query<{ status: string }>(
      'SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = $1',
      [subscription.id]
    );

    // Explicit handling for new subscriptions vs existing ones
    const isNewSubscription = !currentResult.ok || currentResult.value.rows.length === 0;
    
    if (isNewSubscription) {
      // New subscription: Only allow valid initial states
      const VALID_INITIAL_STATES: SubscriptionStatus[] = ['incomplete', 'trialing', 'active'];
      if (!VALID_INITIAL_STATES.includes(newStatus)) {
        logger.error('Invalid initial subscription state', {
          tenantId,
          subscriptionId: subscription.id,
          newStatus,
          validStates: VALID_INITIAL_STATES,
        });
        throw new Error(
          `Invalid initial subscription state: ${newStatus} (expected one of: ${VALID_INITIAL_STATES.join(', ')})`
        );
      }
      logger.info('New subscription created', { tenantId, subscriptionId: subscription.id, status: newStatus });
    } else if (currentResult.ok && currentResult.value.rows.length > 0) {
      const currentRow = currentResult.value.rows[0];
      const currentStatus = (currentRow?.status ?? newStatus) as SubscriptionStatus;
      if (currentStatus !== newStatus) {
        const allowed = StripeService.VALID_STATUS_TRANSITIONS[currentStatus];
        if (allowed && !allowed.includes(newStatus)) {
          logger.error('E-184: Invalid subscription status transition', {
            tenantId,
            subscriptionId: subscription.id,
            currentStatus,
            newStatus,
          });
          throw new Error(
            `Invalid subscription status transition: ${currentStatus} → ${newStatus}`
          );
        }
      }
    }

    const priceId = subscription.items.data[0]?.price.id;
    const interval = subscription.items.data[0]?.price.recurring?.interval;

    // CRITICAL: Use atomic CTE to upsert subscription and update tenant plan in one transaction
    await this.db.query(
      `WITH upsert_subscription AS (
        INSERT INTO stripe_subscriptions (
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
          updated_at = NOW()
        RETURNING tenant_id
      ),
      plan_lookup AS (
        SELECT name FROM plans 
        WHERE stripe_price_id_monthly = $4 OR stripe_price_id_yearly = $4
        LIMIT 1
      ),
      update_tenant AS (
        UPDATE tenants 
        SET plan = COALESCE((SELECT name FROM plan_lookup), plan), updated_at = NOW()
        WHERE id = $1
        RETURNING id
      )
      SELECT 
        EXISTS (SELECT 1 FROM upsert_subscription) as subscription_updated,
        EXISTS (SELECT 1 FROM update_tenant) as tenant_updated`,
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
        subscription.canceled_at ? new Date(subscription.canceled_at * MS_PER_SECOND) : null,
        subscription.trial_end ? new Date(subscription.trial_end * MS_PER_SECOND) : null,
      ]
    );

    logger.info('Subscription updated', { tenantId, subscriptionId: subscription.id, status: subscription.status });

    // Auto-provision dedicated IPs if the plan includes them
    if (subscription.status === 'active') {
      await this.autoProvisionDedicatedIps(tenantId);
    }
  }

  /**
   * Auto-provision dedicated IPs when a tenant's plan includes them.
   * Queries the plan's `dedicated_ip_count` feature and allocates IPs
   * if the tenant doesn't already have enough.
   * Tracks provisioning state and alerts on failures.
   */
  private async autoProvisionDedicatedIps(tenantId: string): Promise<void> {
    try {
      // Check how many IPs the plan includes
      const planResult = await this.db.query<{ included_count: number }>(
        `SELECT COALESCE((p.features->>'dedicated_ip_count')::int, 0) as included_count
         FROM stripe_subscriptions s
         JOIN plans p ON p.name = (
           SELECT plan FROM tenants WHERE id = s.tenant_id
         )
         WHERE s.tenant_id = $1 AND s.status = 'active'
         ORDER BY s.created_at DESC LIMIT 1`,
        [tenantId]
      );

      if (!planResult.ok) return;
      const planRow = planResult.value.rows[0];
      if (!planRow) return;
      const includedCount = planRow.included_count;
      if (includedCount <= 0) return;

      // Check how many they already have
      const activeResult = await this.db.query<{ count: number }>(
        `SELECT COUNT(*)::int as count FROM dedicated_ips
         WHERE tenant_id = $1::uuid AND status NOT IN ('retired', 'releasing')`,
        [tenantId]
      );

      if (!activeResult.ok) return;
      const activeCount = activeResult.value.rows[0]?.count ?? 0;

      const toAllocate = includedCount - activeCount;
      if (toAllocate <= 0) {
        logger.info('Tenant already has sufficient dedicated IPs', { tenantId, activeCount, includedCount });
        return;
      }

      logger.info('Auto-provisioning dedicated IPs', { tenantId, toAllocate, includedCount, activeCount });

      // Track provisioning attempt
      await this.db.query(
        `INSERT INTO dedicated_ip_provisioning_requests 
         (id, tenant_id, requested_count, status, created_at, updated_at)
         VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
         ON CONFLICT (tenant_id) WHERE status = 'pending' 
         DO UPDATE SET requested_count = $2, updated_at = NOW()`,
        [tenantId, toAllocate]
      );

      // Call the internal API to allocate IPs
      const apiBaseUrl = config.apiBaseUrl;
      let successCount = 0;
      let failureCount = 0;

      for (let i = 0; i < toAllocate; i++) {
        try {
          const response = await fetch(`${apiBaseUrl}/v1/dedicated-ips`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${config.serviceAuthToken}`,
              'X-Internal-Service': 'billing',
              'X-Tenant-Id': tenantId,
            },
            body: JSON.stringify({ auto_provisioned: true }),
          });

          if (response.ok) {
            successCount++;
            logger.info('Auto-provisioned dedicated IP', { tenantId, ipNumber: i + 1, total: toAllocate });
          } else {
            failureCount++;
            const errorText = await response.text();
            logger.warn('Failed to auto-provision dedicated IP', {
              tenantId, ipNumber: i + 1, status: response.status, error: errorText,
            });
          }
        } catch (err) {
          failureCount++;
          logger.error('Error auto-provisioning dedicated IP', { tenantId, ipNumber: i + 1, error: err });
        }
      }

      // Update provisioning request status
      const finalStatus = failureCount === 0 ? 'completed' : (successCount > 0 ? 'partial' : 'failed');
      await this.db.query(
        `UPDATE dedicated_ip_provisioning_requests 
         SET status = $2, success_count = $3, failure_count = $4, updated_at = NOW()
         WHERE tenant_id = $1 AND status = 'pending'`,
        [tenantId, finalStatus, successCount, failureCount]
      );

      // Log alert event if there were failures for ops team
      if (failureCount > 0) {
        logger.error('Dedicated IP provisioning had failures - ops action required', {
          tenantId,
          requestedCount: toAllocate,
          successCount,
          failureCount,
          finalStatus,
        });
      }
    } catch (err) {
      // Non-fatal — don't break the subscription flow
      logger.error('Auto-provision dedicated IPs failed', { tenantId, error: err });
      
      // Update provisioning request as failed
      await this.db.query(
        `UPDATE dedicated_ip_provisioning_requests 
         SET status = 'failed', error_message = $2, updated_at = NOW()
         WHERE tenant_id = $1 AND status = 'pending'`,
        [tenantId, err instanceof Error ? err.message : String(err)]
      ).catch(() => { /* ignore DB errors in error handler */ });
    }
  }

  private async handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
    const tenantId = subscription.metadata?.tenant_id;
    if (!tenantId) return;

    // CRITICAL: Atomically cancel subscription and downgrade tenant
    await this.db.query(
      `WITH cancel_subscription AS (
        UPDATE stripe_subscriptions SET status = 'canceled', updated_at = NOW() 
        WHERE stripe_subscription_id = $1
        RETURNING tenant_id
      ),
      downgrade_tenant AS (
        UPDATE tenants SET plan = 'free', updated_at = NOW() 
        WHERE id = $2
        RETURNING id
      )
      SELECT 
        EXISTS (SELECT 1 FROM cancel_subscription) as subscription_canceled,
        EXISTS (SELECT 1 FROM downgrade_tenant) as tenant_downgraded`,
      [subscription.id, tenantId]
    );

    logger.info('Subscription canceled', { tenantId, subscriptionId: subscription.id });
  }

  private async handleInvoicePaid(invoice: Stripe.Invoice): Promise<void> {
    try {
      let tenantId = invoice.subscription_details?.metadata?.tenant_id;

      if (!tenantId) {
        const subscriptionId = typeof invoice.subscription === 'string'
          ? invoice.subscription
          : invoice.subscription?.id;

        if (subscriptionId) {
          const tenantLookup = await this.db.query<{ tenant_id: string }>(
            `SELECT tenant_id
             FROM stripe_subscriptions
             WHERE stripe_subscription_id = $1
             ORDER BY created_at DESC
             LIMIT 1`,
            [subscriptionId]
          );

          if (tenantLookup.ok) {
            tenantId = tenantLookup.value.rows[0]?.tenant_id;
          }
        }
      }

      if (!tenantId) return;

      // Sync invoice to our database
      await this.db.query(
        `UPDATE invoices SET status = 'paid', paid_at = NOW(), updated_at = NOW()
         WHERE stripe_invoice_id = $1`,
        [invoice.id]
      );

      logger.info('Invoice paid', { tenantId, invoiceId: invoice.id });
    } catch (error) {
      logger.error('Failed to handle invoice paid event', { error, invoiceId: invoice.id });
      throw error; // Re-throw so webhook handler can retry
    }
  }

  private async handlePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
    try {
      const tenantId = invoice.subscription_details?.metadata?.tenant_id;
      if (!tenantId) return;

      // Delegate to DunningService for proper retry scheduling, grace periods,
      // and tenant suspension logic (atomic CTE).
      if (this.dunning) {
        const dunningResult = await this.dunning.recordFailedPayment(
          tenantId,
          invoice.id,
          invoice.amount_due,
        );

        const dunningState = dunningResult.ok ? dunningResult.value : null;

        // Queue dunning notification
        await this.db.query(
          `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
           VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())`,
          [tenantId, JSON.stringify({
            invoiceId: invoice.id,
            amount: invoice.amount_due,
            attemptCount: invoice.attempt_count,
            dunningStatus: dunningState?.status ?? 'unknown',
            nextRetryAt: dunningState?.nextRetryAt ?? null,
          })]
        );

        logger.warn('Payment failed — dunning updated via DunningService', {
          tenantId,
          invoiceId: invoice.id,
          attemptCount: invoice.attempt_count,
          dunningStatus: dunningState?.status,
        });
      } else {
        // Fallback: DunningService not injected (should not happen in production)
        logger.error('DunningService not available — payment failure not tracked', {
          tenantId,
          invoiceId: invoice.id,
        });
      }
    } catch (error) {
      logger.error('Failed to handle payment failed event', { error, invoiceId: invoice.id });
      throw error; // Re-throw so webhook handler can retry
    }
  }

  private async handleTrialEnding(subscription: Stripe.Subscription): Promise<void> {
    try {
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

      logger.info('Trial ending soon', { tenantId, subscriptionId: subscription.id });
    } catch (error) {
      logger.error('Failed to handle trial ending event', { error, subscriptionId: subscription.id });
      throw error; // Re-throw so webhook handler can retry
    }
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
      const idempotencyKey = `refund_${paymentIntentId}_${amount ?? 'full'}_${reason ?? 'none'}`;

      const refund = await this.executeStripeCall(
        'refunds.create',
        { paymentIntentId, amount, reason },
        () => this.stripe.refunds.create(
          {
            payment_intent: paymentIntentId,
            amount,
            reason: reason as Stripe.RefundCreateParams.Reason,
          },
          {
            idempotencyKey,
          }
        )
      );

      return Result.ok(refund);
    } catch (error) {
      logger.error('Failed to create refund', { error, paymentIntentId });
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Get subscription status
   */
  async getSubscription(tenantId: string): Promise<Result<StripeSubscription | null, Error>> {
    const result = await this.db.query<StripeSubscriptionRow>(
      `SELECT id, tenant_id, stripe_subscription_id, stripe_customer_id, stripe_price_id,
              status, billing_interval, billing_cycle_start, billing_cycle_end,
              cancel_at_period_end, canceled_at, trial_end, created_at, updated_at
       FROM stripe_subscriptions WHERE tenant_id = $1 AND status != 'canceled' ORDER BY created_at DESC LIMIT 1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok(this.mapStripeSubscription(row));
  }

  private mapStripeCustomer(row: StripeCustomerRow): StripeCustomer {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      stripeCustomerId: row.stripe_customer_id,
      email: row.email,
      name: row.name,
      defaultPaymentMethodId: row.default_payment_method_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private mapStripeSubscription(row: StripeSubscriptionRow): StripeSubscription {
    return {
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
    };
  }

  /**
   * Cancel subscription
   */
  async cancelSubscription(
    stripeSubscriptionId: string,
    options: { cancelAtPeriodEnd?: boolean } = {}
  ): Promise<Result<Stripe.Subscription, Error>> {
    try {
      if (options.cancelAtPeriodEnd) {
        const subscription = await this.executeStripeCall(
          'subscriptions.update.cancel-at-period-end',
          { stripeSubscriptionId },
          () => this.stripe.subscriptions.update(stripeSubscriptionId, {
            cancel_at_period_end: true,
          })
        );
        return Result.ok(subscription);
      } else {
        const subscription = await this.executeStripeCall(
          'subscriptions.cancel',
          { stripeSubscriptionId },
          () => this.stripe.subscriptions.cancel(stripeSubscriptionId)
        );
        return Result.ok(subscription);
      }
    } catch (error) {
      logger.error('Failed to cancel subscription', { error, stripeSubscriptionId });
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Switch subscription to a different plan
   */
  async switchSubscription(
    tenantId: string,
    planName: string,
    billingInterval: 'monthly' | 'yearly' = 'monthly'
  ): Promise<Result<{ subscription: Stripe.Subscription; prorationAmount: number }, Error>> {
    // Get current subscription
    const subscriptionResult = await this.getSubscription(tenantId);
    if (!subscriptionResult.ok) return Result.err(subscriptionResult.error);
    
    if (!subscriptionResult.value) {
      return Result.err(new Error('No active subscription found'));
    }
    const currentSubscription = subscriptionResult.value;

    // Get new plan price ID
    const planResult = await this.db.query<{
      stripe_price_id_monthly: string | null;
      stripe_price_id_yearly: string | null;
    }>(
      `SELECT stripe_price_id_monthly, stripe_price_id_yearly FROM plans WHERE name = $1`,
      [planName]
    );

    if (!planResult.ok) return Result.err(planResult.error);
    
    const plan = planResult.value.rows[0];
    if (!plan) return Result.err(new Error('Plan not found'));

    const newPriceId = billingInterval === 'yearly' 
      ? plan.stripe_price_id_yearly 
      : plan.stripe_price_id_monthly;

    if (!newPriceId) {
      return Result.err(new Error(`No Stripe price configured for ${planName} (${billingInterval})`));
    }

    // Deterministic saga ID so retries of the same switch are idempotent
    // (ON CONFLICT (id) DO NOTHING prevents duplicate saga rows)
    const fromPriceId = currentSubscription.stripePriceId;
    const sagaId = `saga_switch_${tenantId}_${fromPriceId}_${newPriceId}`;
    
    try {
      // Step 1: Record intention in DB (saga start)
      const intentResult = await this.db.query<{ id: string }>(
        `INSERT INTO subscription_change_saga (
          id, tenant_id, subscription_id, from_price_id, to_price_id, 
          from_interval, to_interval, status, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        RETURNING id`,
        [
          sagaId, 
          tenantId, 
          currentSubscription.id,
          currentSubscription.stripePriceId,
          newPriceId,
          currentSubscription.billingInterval,
          billingInterval
        ]
      );

      if (!intentResult.ok) {
        logger.error('Failed to record subscription change intention', { error: intentResult.error, sagaId });
        return Result.err(intentResult.error);
      }

      // Step 2: Get the current subscription from Stripe
      const stripeSubscription = await this.executeStripeCall(
        'subscriptions.retrieve',
        { tenantId, stripeSubscriptionId: currentSubscription.stripeSubscriptionId },
        () => this.stripe.subscriptions.retrieve(
          currentSubscription.stripeSubscriptionId
        )
      );

      // Step 3: Update the subscription with proration in Stripe
      const updatedSubscription = await this.executeStripeCall(
        'subscriptions.update.switch-plan',
        { tenantId, stripeSubscriptionId: currentSubscription.stripeSubscriptionId, newPriceId },
        () => this.stripe.subscriptions.update(
          currentSubscription.stripeSubscriptionId,
          {
            items: [
              {
                id: stripeSubscription.items.data[0]?.id,
                price: newPriceId,
              },
            ],
            proration_behavior: 'create_prorations',
            metadata: {
              ...stripeSubscription.metadata,
              saga_id: sagaId, // Track saga for reconciliation
            },
          }
        )
      );

      // Step 4: Mark saga as stripe_completed
      await this.db.query(
        `UPDATE subscription_change_saga SET status = 'stripe_completed', stripe_response = $2, updated_at = NOW() WHERE id = $1`,
        [sagaId, JSON.stringify({ subscriptionId: updatedSubscription.id, status: updatedSubscription.status })]
      );

      // Step 5: Calculate proration amount from upcoming invoice
      let prorationAmount = 0;
      try {
        const upcomingInvoice = await this.executeStripeCall(
          'invoices.retrieveUpcoming',
          { tenantId, customerId: currentSubscription.stripeCustomerId },
          () => this.stripe.invoices.retrieveUpcoming({
            customer: currentSubscription.stripeCustomerId,
          })
        );
        prorationAmount = upcomingInvoice.lines.data
          .filter(line => line.proration)
          .reduce((sum, line) => sum + line.amount, 0);
      } catch (invoiceError) {
        // Non-fatal: proration calculation failed but subscription was updated
        logger.warn('Failed to calculate proration amount', { error: invoiceError, sagaId });
      }

      // Step 6: Atomically update local database and complete saga
      const finalizeResult = await this.db.query(
        `WITH update_subscription AS (
          UPDATE stripe_subscriptions 
          SET stripe_price_id = $1, billing_interval = $2, updated_at = NOW()
          WHERE id = $3
          RETURNING id
        ),
        update_tenant AS (
          UPDATE tenants SET plan = $4, updated_at = NOW() WHERE id = $5
          RETURNING id
        ),
        complete_saga AS (
          UPDATE subscription_change_saga 
          SET status = 'completed', proration_amount = $6, updated_at = NOW() 
          WHERE id = $7
          RETURNING id
        )
        SELECT 
          EXISTS (SELECT 1 FROM update_subscription) as subscription_updated,
          EXISTS (SELECT 1 FROM update_tenant) as tenant_updated,
          EXISTS (SELECT 1 FROM complete_saga) as saga_completed`,
        [newPriceId, billingInterval, currentSubscription.id, planName, tenantId, prorationAmount, sagaId]
      );

      if (!finalizeResult.ok) {
        // Stripe was updated but DB failed - mark saga for manual reconciliation
        await this.db.query(
          `UPDATE subscription_change_saga SET status = 'db_failed', error = $2, updated_at = NOW() WHERE id = $1`,
          [sagaId, finalizeResult.error.message]
        ).catch((dbErr) => { logger.error('Failed to update saga status to db_failed', { sagaId, dbErr }); });
        
        logger.error('CRITICAL: Stripe updated but DB failed - manual reconciliation required', {
          sagaId,
          tenantId,
          stripeSubscriptionId: updatedSubscription.id,
          error: finalizeResult.error.message,
          action: 'MANUAL_SUBSCRIPTION_RECONCILIATION_REQUIRED'
        });
        return Result.err(finalizeResult.error);
      }

      logger.info('Subscription switch completed', { sagaId, tenantId, planName, billingInterval });

      return Result.ok({
        subscription: updatedSubscription,
        prorationAmount,
      });
    } catch (error) {
      // Mark saga as failed for investigation
      await this.db.query(
        `UPDATE subscription_change_saga 
         SET status = 'failed', error = $2, updated_at = NOW() 
         WHERE id = $1`,
        [sagaId, error instanceof Error ? error.message : String(error)]
      ).catch((dbErr) => { logger.error('Failed to update saga status to failed', { sagaId, dbErr }); });
      
      logger.error('Failed to switch subscription', { error, tenantId, planName, sagaId });
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async cleanupStuckSubscriptionSagas(): Promise<Result<{ cleaned: number }, Error>> {
    const timeoutMinutes = config.sagaTimeoutMinutes;
    
    const result = await this.db.query<{ cleaned: string }>(
      `WITH updated AS (
         UPDATE subscription_change_saga
         SET status = 'failed',
             error = COALESCE(error, 'Timed out waiting for completion'),
             updated_at = NOW()
         WHERE status IN ('pending', 'stripe_completed')
           AND updated_at < NOW() - INTERVAL '${timeoutMinutes} minutes'
         RETURNING id
       )
       SELECT COUNT(*)::text AS cleaned FROM updated`
    );

    if (!result.ok) return Result.err(result.error);
    return Result.ok({ cleaned: parseInt(result.value.rows[0]?.cleaned ?? '0', 10) });
  }

  async processScheduledRetries(): Promise<Result<{ attempted: number; succeeded: number }, Error>> {
    const dueResult = await this.db.query<{
      tenant_id: string;
      stripe_subscription_id: string;
      stripe_customer_id: string;
    }>(
      `SELECT d.tenant_id, s.stripe_subscription_id, s.stripe_customer_id
       FROM dunning_records d
       JOIN stripe_subscriptions s ON s.tenant_id = d.tenant_id
       WHERE d.next_retry_at IS NOT NULL
         AND d.next_retry_at <= NOW()
         AND d.status IN ('warning', 'soft_suspended')
         AND s.status IN ('past_due', 'unpaid')
       ORDER BY d.next_retry_at ASC
       LIMIT 50`
    );

    if (!dueResult.ok) return Result.err(dueResult.error);

    let attempted = 0;
    let succeeded = 0;

    for (const row of dueResult.value.rows) {
      attempted += 1;

      try {
        const invoices = await this.executeStripeCall(
          'invoices.list',
          { tenantId: row.tenant_id, stripeCustomerId: row.stripe_customer_id },
          () => this.stripe.invoices.list({
            customer: row.stripe_customer_id,
            subscription: row.stripe_subscription_id,
            status: 'open',
            limit: 1,
          })
        );

        const invoice = invoices.data[0];
        if (!invoice?.id) {
          await this.db.query(
            `UPDATE dunning_records
             SET next_retry_at = NULL, updated_at = NOW()
             WHERE tenant_id = $1`,
            [row.tenant_id]
          );
          continue;
        }

        await this.executeStripeCall(
          'invoices.pay',
          { tenantId: row.tenant_id, invoiceId: invoice.id },
          () => this.stripe.invoices.pay(invoice.id)
        );
        succeeded += 1;

        if (this.dunning) {
          await this.dunning.recordSuccessfulPayment(row.tenant_id);
        } else {
          await this.db.query(
            `UPDATE dunning_records
             SET status = 'healthy',
                 failed_payment_count = 0,
                 first_failed_at = NULL,
                 last_failed_at = NULL,
                 next_retry_at = NULL,
                 updated_at = NOW()
             WHERE tenant_id = $1`,
            [row.tenant_id]
          );
        }
      } catch (error) {
        logger.warn('Scheduled Stripe retry failed', {
          tenantId: row.tenant_id,
          error: error instanceof Error ? error.message : String(error),
        });

        await this.db.query(
          `UPDATE dunning_records
           SET next_retry_at = NOW() + INTERVAL '1 day', updated_at = NOW()
           WHERE tenant_id = $1`,
          [row.tenant_id]
        ).catch(() => undefined);
      }
    }

    return Result.ok({ attempted, succeeded });
  }
}
