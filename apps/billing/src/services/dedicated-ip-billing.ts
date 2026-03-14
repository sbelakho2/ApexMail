/**
 * Dedicated IP Billing Service
 *
 * Manages Stripe subscription items for dedicated IP add-ons.
 * Runs as a periodic sync job in the billing service.
 *
 * Flow:
 * 1. API app provisions IP → sets billing_status = 'pending_charge' or 'included'
 * 2. This service picks up 'pending_charge' rows → creates Stripe subscription items
 * 3. API app releases IP → sets billing_status = 'pending_cancel'
 * 4. This service picks up 'pending_cancel' rows → removes Stripe subscription items
 *
 * Plan gating logic lives in the API. This service only manages billing.
 * IPs that are within the plan's included count are set as 'included' by the API
 * and are never charged here.
 *
 * Architecture note: AWS SES is the internal IP provider — NEVER referenced
 * in customer-facing billing descriptions.
 */

import Stripe from 'stripe';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import { getStripe } from '../lib/stripe-client.js';
import { config } from '../config.js';
import { DEDICATED_IP_ADDON_PRICE_CENTS } from '../lib/constants.js';
import { StripeCircuitBreaker } from './stripe-circuit-breaker.js';

const logger = createLogger();

/** Stripe price ID for the $30/mo dedicated IP add-on */
function getDedicatedIpPriceId(): Result<string, Error> {
  const priceId = config.stripeDedicatedIpPriceId;
  if (!priceId) {
    return Result.err(new Error('STRIPE_DEDICATED_IP_PRICE_ID is not configured'));
  }
  return Result.ok(priceId);
}

// DEDICATED_IP_ADDON_PRICE_CENTS imported from ../lib/constants.js

interface PendingIpRow {
  [key: string]: unknown;
  id: string;
  tenant_id: string;
  ip_address: string;
  billing_status: string;
  stripe_subscription_item_id: string | null;
}

interface TenantSubscription {
  [key: string]: unknown;
  stripe_subscription_id: string;
  stripe_customer_id: string;
}

export class DedicatedIpBillingService {
  private readonly stripe: Stripe;
  private readonly circuitBreaker: StripeCircuitBreaker;
  private syncTimer: NodeJS.Timeout | null = null;

  constructor(private readonly db: DatabasePool) {
    this.stripe = getStripe();
    this.circuitBreaker = new StripeCircuitBreaker();
  }

  private async executeStripeCall<T>(
    operation: string,
    metadata: Record<string, unknown>,
    fn: () => Promise<T>,
  ): Promise<T> {
    try {
      return await this.circuitBreaker.execute(fn);
    } catch (error) {
      logger.error(`Dedicated IP Stripe operation failed: ${operation}`, {
        ...metadata,
        error: error instanceof Error ? error.message : String(error),
        circuitState: this.circuitBreaker.getState(),
      });
      throw error;
    }
  }

  /**
   * Start the periodic billing sync.
   * Runs every 30 seconds to pick up pending charges/cancels promptly.
   */
  startSync(intervalMs = 30_000): void {
    if (this.syncTimer) return;
    this.syncTimer = setInterval(() => {
      void this.syncAll().catch(err =>
        logger.error('Dedicated IP billing sync failed', { error: String(err) }),
      );
    }, intervalMs);

    // Run immediately on start
    void this.syncAll().catch(err =>
      logger.error('Dedicated IP billing initial sync failed', { error: String(err) }),
    );
  }

  /**
   * Stop the periodic sync (for graceful shutdown).
   */
  stopSync(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  /**
   * Main sync entry point. Processes both pending charges and pending cancels.
   */
  async syncAll(): Promise<Result<{ charged: number; canceled: number }, Error>> {
    let charged = 0;
    let canceled = 0;

    // Process pending charges
    const chargeResult = await this.processPendingCharges();
    if (chargeResult.ok) charged = chargeResult.value;

    // Process pending cancels
    const cancelResult = await this.processPendingCancels();
    if (cancelResult.ok) canceled = cancelResult.value;

    if (charged > 0 || canceled > 0) {
      logger.info('Dedicated IP billing sync completed', { charged, canceled });
    }

    return Result.ok({ charged, canceled });
  }

  /**
   * Find IPs with billing_status = 'pending_charge' and create Stripe subscription items.
   */
  private async processPendingCharges(): Promise<Result<number, Error>> {
    const priceId = config.stripeDedicatedIpPriceId;
    if (!priceId) {
      // No Stripe price configured — skip (dev/test environment)
      return Result.ok(0);
    }

    const pendingResult = await this.db.query<PendingIpRow>(
      `SELECT id, tenant_id, ip_address, billing_status, stripe_subscription_item_id
       FROM dedicated_ips
       WHERE billing_status = 'pending_charge'
         AND (billing_retry_after IS NULL OR billing_retry_after <= NOW())
       ORDER BY created_at ASC
       LIMIT 50
       FOR UPDATE SKIP LOCKED`,
    );

    if (!pendingResult.ok) {
      logger.error('Failed to fetch pending charge IPs', { error: pendingResult.error.message });
      return Result.err(pendingResult.error);
    }

    let processed = 0;
    for (const ip of pendingResult.value.rows) {
      const result = await this.chargeForIp(ip);
      if (result.ok) processed++;
    }

    return Result.ok(processed);
  }

  /**
   * Create a Stripe subscription item for a single dedicated IP add-on.
   */
  private async chargeForIp(ip: PendingIpRow): Promise<Result<void, Error>> {
    // Get the tenant's active Stripe subscription
    const subResult = await this.db.query<TenantSubscription>(
      `SELECT stripe_subscription_id, stripe_customer_id
       FROM stripe_subscriptions
       WHERE tenant_id = $1 AND status = 'active'
       ORDER BY created_at DESC
       LIMIT 1`,
      [ip.tenant_id],
    );

    if (!subResult.ok) return Result.err(subResult.error);

    const sub = subResult.value.rows[0];
    if (!sub) {
      // No active subscription — mark retry metadata so the row is not stuck hot-looping in pending_charge.
      await this.db.query(
        `UPDATE dedicated_ips SET
           billing_failure_count = COALESCE(billing_failure_count, 0) + 1,
           billing_retry_after = NOW() + (
             LEAST(POWER(2, LEAST(COALESCE(billing_failure_count, 0), 5)), 30) || ' minutes'
           )::interval,
           updated_at = NOW()
         WHERE id = $1`,
        [ip.id],
      ).catch((dbErr: unknown) => { logger.error('Failed to update pending charge retry metadata', { ipId: ip.id, dbErr: String(dbErr) }); });

      logger.warn('No active Stripe subscription for tenant, skipping IP billing', {
        tenantId: ip.tenant_id,
        ipId: ip.id,
      });
      return Result.err(new Error('No active Stripe subscription for tenant'));
    }

    try {
      const priceIdResult = getDedicatedIpPriceId();
      if (!priceIdResult.ok) {
        return Result.err(priceIdResult.error);
      }

      // Create a new subscription item for this dedicated IP
      const subscriptionItem = await this.executeStripeCall(
        'subscriptionItems.create',
        { tenantId: ip.tenant_id, ipId: ip.id },
        () => this.stripe.subscriptionItems.create(
          {
            subscription: sub.stripe_subscription_id,
            price: priceIdResult.value,
            quantity: 1,
            proration_behavior: 'create_prorations',
            metadata: {
              apexmail_ip_id: ip.id,
              apexmail_tenant_id: ip.tenant_id,
              type: 'dedicated_ip_addon',
            },
          },
          { idempotencyKey: `apexmail_ip_charge_${ip.id}` },
        ),
      );

      // Update the IP record with the subscription item ID
      await this.db.query(
        `UPDATE dedicated_ips SET
           billing_status = 'active',
           stripe_subscription_item_id = $2,
           billing_started_at = NOW(),
           updated_at = NOW()
         WHERE id = $1`,
        [ip.id, subscriptionItem.id],
      );

      logger.info('Stripe subscription item created for dedicated IP', {
        tenantId: ip.tenant_id,
        ipId: ip.id,
        subscriptionItemId: subscriptionItem.id,
        monthlyCharge: DEDICATED_IP_ADDON_PRICE_CENTS,
      });

      return Result.ok(undefined);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      logger.error('Failed to create Stripe subscription item for dedicated IP', {
        tenantId: ip.tenant_id,
        ipId: ip.id,
        error: msg,
      });

      // Exponential backoff: retry after 1min, 2min, 4min, 8min, then cap at 30min
      await this.db.query(
        `UPDATE dedicated_ips SET
           billing_failure_count = COALESCE(billing_failure_count, 0) + 1,
           billing_retry_after = NOW() + (
             LEAST(POWER(2, LEAST(COALESCE(billing_failure_count, 0), 5)), 30) || ' minutes'
           )::interval,
           updated_at = NOW()
         WHERE id = $1`,
        [ip.id],
      ).catch((dbErr: unknown) => { logger.error('Failed to update billing failure count', { ipId: ip.id, dbErr: String(dbErr) }); });

      return Result.err(error instanceof Error ? error : new Error(msg));
    }
  }

  /**
   * Find IPs with billing_status = 'pending_cancel' and remove Stripe subscription items.
   */
  private async processPendingCancels(): Promise<Result<number, Error>> {
    const pendingResult = await this.db.query<PendingIpRow>(
      `SELECT id, tenant_id, ip_address, billing_status, stripe_subscription_item_id
       FROM dedicated_ips
       WHERE billing_status = 'pending_cancel'
       ORDER BY updated_at ASC
       LIMIT 50
       FOR UPDATE SKIP LOCKED`,
    );

    if (!pendingResult.ok) {
      logger.error('Failed to fetch pending cancel IPs', { error: pendingResult.error.message });
      return Result.err(pendingResult.error);
    }

    let processed = 0;
    for (const ip of pendingResult.value.rows) {
      const result = await this.cancelBillingForIp(ip);
      if (result.ok) processed++;
    }

    return Result.ok(processed);
  }

  /**
   * Remove a Stripe subscription item for a released dedicated IP.
   */
  private async cancelBillingForIp(ip: PendingIpRow): Promise<Result<void, Error>> {
    if (ip.stripe_subscription_item_id) {
      try {
        // Delete the subscription item with proration (customer gets credit for unused time)
        await this.executeStripeCall(
          'subscriptionItems.delete',
          {
            tenantId: ip.tenant_id,
            ipId: ip.id,
            subscriptionItemId: ip.stripe_subscription_item_id,
          },
          () => this.stripe.subscriptionItems.del(ip.stripe_subscription_item_id, {
            proration_behavior: 'create_prorations',
          }),
        );

        logger.info('Stripe subscription item removed for dedicated IP', {
          tenantId: ip.tenant_id,
          ipId: ip.id,
          subscriptionItemId: ip.stripe_subscription_item_id,
        });
      } catch (error) {
        // If the subscription item doesn't exist in Stripe (already deleted), continue
        if (error instanceof Stripe.errors.StripeError && error.code === 'resource_missing') {
          logger.warn('Stripe subscription item already deleted', {
            ipId: ip.id,
            subscriptionItemId: ip.stripe_subscription_item_id,
          });
        } else {
          const msg = error instanceof Error ? error.message : String(error);
          logger.error('Failed to delete Stripe subscription item', {
            ipId: ip.id,
            subscriptionItemId: ip.stripe_subscription_item_id,
            error: msg,
          });
          return Result.err(error instanceof Error ? error : new Error(msg));
        }
      }
    }

    // Mark as canceled regardless (handles both Stripe-billed and included IPs)
    await this.db.query(
      `UPDATE dedicated_ips SET
         billing_status = 'canceled',
         billing_ended_at = NOW(),
         updated_at = NOW()
       WHERE id = $1`,
      [ip.id],
    );

    return Result.ok(undefined);
  }

  /**
   * Get billing summary for a tenant's dedicated IPs.
   * Used by the admin dashboard and billing routes.
   */
  async getBillingSummary(tenantId: string): Promise<Result<{
    includedIps: number;
    billedIps: number;
    monthlyAddOnCharge: number; // In cents
    stripeItemIds: string[];
  }, Error>> {
    const result = await this.db.query<{
      [key: string]: unknown;
      billing_status: string;
      stripe_subscription_item_id: string | null;
    }>(
      `SELECT billing_status, stripe_subscription_item_id
       FROM dedicated_ips
       WHERE tenant_id = $1 AND status NOT IN ('retired')`,
      [tenantId],
    );

    if (!result.ok) return Result.err(result.error);

    let includedIps = 0;
    let billedIps = 0;
    const stripeItemIds: string[] = [];

    for (const row of result.value.rows) {
      if (row.billing_status === 'included') {
        includedIps++;
      } else if (row.billing_status === 'active' || row.billing_status === 'pending_charge') {
        billedIps++;
        if (row.stripe_subscription_item_id) {
          stripeItemIds.push(row.stripe_subscription_item_id);
        }
      }
    }

    return Result.ok({
      includedIps,
      billedIps,
      monthlyAddOnCharge: billedIps * DEDICATED_IP_ADDON_PRICE_CENTS,
      stripeItemIds,
    });
  }
}
