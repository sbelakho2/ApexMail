/**
 * Billing Routes - API endpoints for billing operations
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { withTransaction } from '@apexmail/db';
import type { BillingEnv, BillingContext } from '../app.js';
import { calculateOverageCost, calculatePaygCost, PAYG_PRICING } from '../services/plans.js';
import { logger } from '../lib/logger.js';

export function billingRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();
  type RouteContext = Parameters<typeof router.get>[1] extends (arg: infer C) => unknown ? C : never;

  const operationFailed = (c: RouteContext, error: unknown, label = 'Billing operation failed') => {
    logger.error(label, { error: error instanceof Error ? error.message : String(error) });
    return c.json({ error: 'Operation failed' }, 500);
  };

  const parseJsonBody = async (c: RouteContext): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> => {
    try {
      const value = await c.req.json();
      return { ok: true, value };
    } catch {
      return { ok: false, response: c.json({ error: 'Invalid JSON body' }, 400) };
    }
  };

  const parseJsonWithSchema = async <T extends z.ZodTypeAny>(
    c: RouteContext,
    schema: T,
  ): Promise<{ ok: true; value: z.infer<T> } | { ok: false; response: Response }> => {
    const parsedBody = await parseJsonBody(c);
    if (!parsedBody.ok) {
      return parsedBody;
    }

    const validated = schema.safeParse(parsedBody.value);
    if (!validated.success) {
      return {
        ok: false,
        response: c.json(
          {
            error: 'Validation failed',
            issues: validated.error.issues,
          },
          400,
        ),
      };
    }

    return { ok: true, value: validated.data };
  };

  const isAllowedRedirectUrl = (urlString: string): boolean => {
    try {
      const url = new URL(urlString);
      const hostname = url.hostname.toLowerCase();
      const isApexmailHost = hostname === 'apexmail.ee' || hostname.endsWith('.apexmail.ee');

      if (isApexmailHost) {
        return url.protocol === 'https:';
      }

      if (process.env.NODE_ENV !== 'production' && hostname === 'localhost') {
        return url.protocol === 'http:' || url.protocol === 'https:';
      }

      return false;
    } catch {
      return false;
    }
  };

  // Get usage summary
  router.get('/usage', async (c) => {
    const tenantId = c.get('tenantId');
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    const result = await ctx.metering.getUsage(tenantId, periodStart, periodEnd);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value);
  });

  // Get real-time counter
  router.get('/usage/realtime/:metric', async (c) => {
    const tenantId = c.get('tenantId');
    const metricSchema = z.enum(['emails_sent', 'api_calls']);
    const metric = metricSchema.parse(c.req.param('metric'));
    const now = new Date();
    const periodKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    const result = await ctx.metering.getRealtimeCounter(tenantId, metric, periodKey);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json({ metric, count: result.value, period: periodKey });
  });

  // Configure usage alerts
  router.post('/alerts', async (c) => {
    const tenantId = c.get('tenantId');

    const schema = z.object({
      thresholds: z.array(z.object({
        metricType: z.enum(['emails', 'api_calls', 'storage']),
        thresholdPercent: z.number().min(1).max(100),
        notificationChannel: z.enum(['email', 'webhook', 'both']),
      })),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;
    const result = await ctx.usageAlerts.configureThresholds(tenantId, parsed.thresholds);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value, 201);
  });

  // Get subscription details
  router.get('/subscription', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.stripe.getSubscription(tenantId);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    if (!result.value) {
      return c.json({ subscription: null, message: 'No active subscription' });
    }

    return c.json({ subscription: result.value });
  });

  // Create checkout session
  router.post('/checkout', async (c) => {
    const tenantId = c.get('tenantId');

    const schema = z.object({
      priceId: z.string().trim().min(1, 'priceId is required'),
      // SEC-011 FIX: Check exact domain match to prevent bypass via evil-apexmail.ee
      successUrl: z.string().url().refine(
        isAllowedRedirectUrl,
        'Redirect URL must belong to apexmail.ee domain'
      ),
      cancelUrl: z.string().url().refine(
        isAllowedRedirectUrl,
        'Redirect URL must belong to apexmail.ee domain'
      ),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;

    const result = await ctx.stripe.createCheckoutSession(
      tenantId,
      parsed.priceId,
      parsed.successUrl,
      parsed.cancelUrl
    );

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value);
  });

  // Create portal session
  router.post('/portal', async (c) => {
    const tenantId = c.get('tenantId');

    const schema = z.object({
      // SEC-011 FIX: Check exact domain match to prevent bypass
      returnUrl: z.string().url().refine(
        isAllowedRedirectUrl,
        'Redirect URL must belong to apexmail.ee domain'
      ),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;

    const result = await ctx.stripe.createPortalSession(tenantId, parsed.returnUrl);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value);
  });

  // Get proration preview
  router.get('/proration/:planName', async (c) => {
    const tenantId = c.get('tenantId');
    const planName = c.req.param('planName');

    const result = await ctx.proration.previewProration(tenantId, planName);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value);
  });

  // Get invoices
  router.get('/invoices', async (c) => {
    const tenantId = c.get('tenantId');
    const limit = Math.min(Math.max(parseInt(c.req.query('limit') ?? '50', 10) || 50, 1), 200);
    const offset = Math.max(parseInt(c.req.query('offset') ?? '0', 10) || 0, 0);

    const result = await ctx.invoices.listInvoices(tenantId, { limit, offset });

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json({
      invoices: result.value.invoices,
      totalCount: result.value.totalCount,
      limit,
      offset,
    });
  });

  // Get invoice details
  router.get('/invoices/:id', async (c) => {
    const invoiceId = c.req.param('id');
    const tenantId = c.get('tenantId');

    const result = await ctx.invoices.getInvoice(invoiceId, tenantId);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    if (!result.value) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    // FIX-016: Verify the invoice belongs to the requesting tenant
    if (result.value.tenantId !== tenantId) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    return c.json(result.value);
  });

  // Get invoice PDF
  router.get('/invoices/:id/pdf', async (c) => {
    const invoiceId = c.req.param('id');
    const tenantId = c.get('tenantId');

    const result = await ctx.invoices.getInvoice(invoiceId, tenantId);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    if (!result.value) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    // FIX-016: Verify the invoice belongs to the requesting tenant
    if (result.value.tenantId !== tenantId) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    const htmlContent = ctx.invoices.generateInvoiceHtml(result.value);

    return c.html(htmlContent);
  });

  // Get invoice e-Invoice XML
  router.get('/invoices/:id/xml', async (c) => {
    const invoiceId = c.req.param('id');
    const tenantId = c.get('tenantId');

    const result = await ctx.invoices.getInvoice(invoiceId, tenantId);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    if (!result.value) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    // FIX-016: Verify the invoice belongs to the requesting tenant
    if (result.value.tenantId !== tenantId) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    const xmlContent = ctx.invoices.generateEInvoiceXml(result.value);

    return c.text(xmlContent, 200, {
      'Content-Type': 'application/xml',
      'Content-Disposition': `attachment; filename="invoice-${result.value.invoiceNumber}.xml"`,
    });
  });

  // Get wallet balance
  router.get('/wallet', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.wallet.getBalance(tenantId);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value);
  });

  // Get wallet transactions
  router.get('/wallet/transactions', async (c) => {
    const tenantId = c.get('tenantId');
    const limit = Math.min(Math.max(parseInt(c.req.query('limit') ?? '50', 10) || 50, 1), 200);
    const offset = Math.max(parseInt(c.req.query('offset') ?? '0', 10) || 0, 0);
    const rawType = c.req.query('type');
    const type = rawType === 'credit' || rawType === 'debit' ? rawType : undefined;

    const result = await ctx.wallet.getTransactions(tenantId, { limit, offset, type });

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json({ transactions: result.value });
  });

  // Get SLA credits
  router.get('/credits', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.slaCredits.getPendingCredits(tenantId);

    if (!result.ok) {
      return operationFailed(c, result.error);
    }

    return c.json(result.value);
  });

  // Get dunning status
  router.get('/dunning', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.dunning.getFullState(tenantId);

    if (!result.ok) {
      logger.error('Billing operation failed', { error: String(result.error), operation: 'getDunning' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value ?? { status: 'healthy' });
  });

  // Get cost report
  router.get('/costs', async (c) => {
    const tenantId = c.get('tenantId');
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);

    const result = await ctx.costCircuit.getCostReport(tenantId, periodStart, now);

    if (!result.ok) {
      logger.error('Billing operation failed', { error: String(result.error), operation: 'getCosts' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Get viral stats
  router.get('/viral/stats', async (c) => {
    const tenantId = c.get('tenantId');
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);

    const result = await ctx.viralLoop.getStats(tenantId, periodStart, now);

    if (!result.ok) {
      logger.error('Billing operation failed', { error: String(result.error), operation: 'getViralStats' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Get PAYG pricing info
  router.get('/payg/pricing', async (c) => {
    return c.json({
      emailPricing: PAYG_PRICING.emailPricing,
      apiPricing: PAYG_PRICING.apiPricing,
      minimumMonthlyCharge: PAYG_PRICING.minimumMonthlyCharge,
    });
  });

  // Calculate PAYG cost estimate
  router.post('/payg/estimate', async (c) => {
    const schema = z.object({
      emailsSent: z.number().min(0),
      apiCalls: z.number().min(0).optional().default(0),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;
    const cost = calculatePaygCost(parsed.emailsSent, parsed.apiCalls);

    return c.json({
      usage: {
        emailsSent: parsed.emailsSent,
        apiCalls: parsed.apiCalls,
      },
      cost,
      pricing: PAYG_PRICING,
    });
  });

  // Calculate subscription overage estimate
  router.post('/overage/estimate', async (c) => {
    const schema = z.object({
      emailsSent: z.number().min(0),
      emailLimit: z.number(),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;
    const overageCostCents = calculateOverageCost(parsed.emailsSent, parsed.emailLimit);

    return c.json({
      usage: {
        emailsSent: parsed.emailsSent,
        emailLimit: parsed.emailLimit,
      },
      overageCostCents,
      overageCostUsd: `$${(overageCostCents / 100).toFixed(2)}`,
    });
  });

  // Get PAYG current period usage and cost
  router.get('/payg/usage', async (c) => {
    const tenantId = c.get('tenantId');
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    const usageResult = await ctx.metering.getUsage(tenantId, periodStart, periodEnd);

    if (!usageResult.ok) {
      return operationFailed(c, usageResult.error, 'Usage check failed');
    }

    const usage = usageResult.value;
    const emailsSent = usage.metrics.emails_sent ?? 0;
    const apiCalls = usage.metrics.api_calls ?? 0;
    const cost = calculatePaygCost(emailsSent, apiCalls);

    return c.json({
      period: {
        start: periodStart.toISOString(),
        end: periodEnd.toISOString(),
      },
      usage: {
        emailsSent,
        apiCalls,
      },
      cost,
      pricing: PAYG_PRICING,
    });
  });

  // Switch plan (handles proration)
  router.post('/switch-plan', async (c) => {
    const tenantId = c.get('tenantId');

    const schema = z.object({
      planName: z.string(),
      billingInterval: z.enum(['monthly', 'yearly']).optional().default('monthly'),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;

    // Check if switching to PAYG
    if (parsed.planName === 'payg') {
      // For PAYG, we need to cancel the current subscription and set up usage-based billing
      const subscriptionResult = await ctx.stripe.getSubscription(tenantId);
      
      if (subscriptionResult.ok && subscriptionResult.value) {
        // Cancel existing subscription at period end
        const cancelResult = await ctx.stripe.cancelSubscription(
          subscriptionResult.value.stripeSubscriptionId,
          { cancelAtPeriodEnd: true }
        );

        if (!cancelResult.ok) {
          return operationFailed(c, cancelResult.error, 'Cancel failed');
        }
      }

      const previousSub = subscriptionResult.ok ? subscriptionResult.value : null;
      const effectiveDate = previousSub?.billingCycleEnd ?? new Date().toISOString();

      // Atomically update tenant plan and append audit trail to avoid partial local state updates
      const localUpdateResult = await withTransaction(ctx.db, async (tx) => {
        const updateResult = await tx.client.query(
          `UPDATE tenants SET plan = 'payg', updated_at = NOW() WHERE id = $1`,
          [tenantId]
        );

        if (updateResult.rowCount !== 1) {
          throw new Error('Failed to update tenant plan');
        }

        const auditResult = await tx.client.query(
          `INSERT INTO audit_logs (id, tenant_id, action, resource_type, metadata, created_at)
           VALUES (gen_random_uuid(), $1, 'plan.changed', 'subscription',
                   $2::jsonb, NOW())`,
          [
            tenantId,
            JSON.stringify({
              previousPlan: previousSub ? 'subscription' : 'unknown',
              newPlan: 'payg',
              changeType: 'downgrade',
              effectiveDate,
            }),
          ]
        );

        if (auditResult.rowCount !== 1) {
          throw new Error('Failed to write audit log');
        }
      });

      if (!localUpdateResult.ok) {
        logger.error('Update failed', { error: String(localUpdateResult.error), operation: 'switchToPAYG' }); return c.json({ error: "Operation failed" }, 500);
      }

      return c.json({
        success: true,
        message: 'Switched to Pay As You Go billing',
        effectiveDate,
      });
    }

    // For regular plans, use proration service
    const previewResult = await ctx.proration.previewProration(tenantId, parsed.planName);

    if (!previewResult.ok) {
      logger.error('Preview failed', { error: String(previewResult.error), operation: 'switchPlan' }); return c.json({ error: "Operation failed" }, 500);
    }

    // Apply the plan change
    const switchResult = await ctx.stripe.switchSubscription(
      tenantId,
      parsed.planName,
      parsed.billingInterval
    );

    if (!switchResult.ok) {
      return c.json({ error: switchResult.error.message }, 500);
    }

    // E-170: Audit trail for plan change
    const auditResult = await ctx.db.query(
      `INSERT INTO audit_logs (id, tenant_id, action, resource_type, metadata, created_at)
       VALUES (gen_random_uuid(), $1, 'plan.changed', 'subscription',
               $2::jsonb, NOW())`,
      [
        tenantId,
        JSON.stringify({
          newPlan: parsed.planName,
          billingInterval: parsed.billingInterval,
          proration: previewResult.value,
          changeType: previewResult.value.netAmount >= 0 ? 'upgrade' : 'downgrade',
        }),
      ]
    );

    if (!auditResult.ok || auditResult.value.rowCount !== 1) {
      logger.error('Audit insert failed', { error: String(auditResult.ok ? 'No audit row inserted' : auditResult.error), operation: 'switchPlan' });
      return c.json({ error: 'Failed to persist audit log' }, 500);
    }

    return c.json({
      success: true,
      proration: previewResult.value,
      newPlan: parsed.planName,
      billingInterval: parsed.billingInterval,
    });
  });

  // Cancel subscription
  router.post('/cancel', async (c) => {
    const tenantId = c.get('tenantId');

    const schema = z.object({
      reason: z.string().max(500).optional(),
      feedback: z.string().max(2000).optional(),
      cancelImmediately: z.boolean().optional().default(false),
    });

    const parsedResult = await parseJsonWithSchema(c, schema);
    if (!parsedResult.ok) {
      return parsedResult.response;
    }

    const parsed = parsedResult.value;

    // Get current subscription
    const subscriptionResult = await ctx.stripe.getSubscription(tenantId);

    if (!subscriptionResult.ok) {
      return operationFailed(c, subscriptionResult.error, 'Failed to fetch subscription');
    }

    if (!subscriptionResult.value) {
      return c.json({ error: 'No active subscription found' }, 404);
    }

    const subscription = subscriptionResult.value;

    // Cancel the subscription
    const cancelResult = await ctx.stripe.cancelSubscription(
      subscription.stripeSubscriptionId,
      { cancelAtPeriodEnd: !parsed.cancelImmediately }
    );

    if (!cancelResult.ok) {
      return operationFailed(c, cancelResult.error, 'Failed to cancel subscription');
    }

    // Determine effective date
    const effectiveDate = parsed.cancelImmediately
      ? new Date().toISOString()
      : subscription.billingCycleEnd;

    // Update tenant plan if immediate cancellation
    if (parsed.cancelImmediately) {
      const updateResult = await ctx.db.query(
        `UPDATE tenants SET plan = 'free', updated_at = NOW() WHERE id = $1`,
        [tenantId]
      );

      if (!updateResult.ok || updateResult.value.rowCount !== 1) {
        logger.error('Failed to update tenant plan after cancellation', { tenantId });
      }
    }

    // Audit trail for cancellation
    const auditResult = await ctx.db.query(
      `INSERT INTO audit_logs (id, tenant_id, action, resource_type, metadata, created_at)
       VALUES (gen_random_uuid(), $1, 'subscription.cancelled', 'subscription',
               $2::jsonb, NOW())`,
      [
        tenantId,
        JSON.stringify({
          previousPlan: subscription.plan,
          reason: parsed.reason ?? 'not provided',
          feedback: parsed.feedback ?? null,
          cancelImmediately: parsed.cancelImmediately,
          effectiveDate,
        }),
      ]
    );

    if (!auditResult.ok || auditResult.value.rowCount !== 1) {
      logger.error('Failed to write cancellation audit log', { tenantId });
    }

    return c.json({
      success: true,
      message: parsed.cancelImmediately
        ? 'Subscription cancelled immediately'
        : 'Subscription will be cancelled at the end of the billing period',
      effectiveDate,
      willDowngradeTo: 'free',
    });
  });

  return router;
}
