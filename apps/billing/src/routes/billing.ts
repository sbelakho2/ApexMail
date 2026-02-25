/**
 * Billing Routes - API endpoints for billing operations
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { BillingEnv, BillingContext } from '../app.js';
import { calculatePaygCost, PAYG_PRICING } from '../services/plans.js';

export function billingRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  // Get usage summary
  router.get('/usage', async (c) => {
    const tenantId = c.get('tenantId');
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    const result = await ctx.metering.getUsage(tenantId, periodStart, periodEnd);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Get real-time counter
  router.get('/usage/realtime/:metric', async (c) => {
    const tenantId = c.get('tenantId');
    const metric = c.req.param('metric') as 'emails_sent' | 'api_calls';
    const now = new Date();
    const periodKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    const result = await ctx.metering.getRealtimeCounter(tenantId, metric, periodKey);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ metric, count: result.value, period: periodKey });
  });

  // Configure usage alerts
  router.post('/alerts', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      thresholds: z.array(z.object({
        metricType: z.enum(['emails', 'api_calls', 'storage']),
        thresholdPercent: z.number().min(1).max(100),
        notificationChannel: z.enum(['email', 'webhook', 'both']),
      })),
    });

    const parsed = schema.parse(body);
    const result = await ctx.usageAlerts.configureThresholds(tenantId, parsed.thresholds);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value, 201);
  });

  // Get subscription details
  router.get('/subscription', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.stripe.getSubscription(tenantId);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    if (!result.value) {
      return c.json({ subscription: null, message: 'No active subscription' });
    }

    return c.json({ subscription: result.value });
  });

  // Create checkout session
  router.post('/checkout', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      priceId: z.string(),
      successUrl: z.string().url().refine(
        (u) => { try { const h = new URL(u).hostname; return h.endsWith('apexmail.ee') || h === 'localhost'; } catch { return false; } },
        'Redirect URL must belong to apexmail.ee'
      ),
      cancelUrl: z.string().url().refine(
        (u) => { try { const h = new URL(u).hostname; return h.endsWith('apexmail.ee') || h === 'localhost'; } catch { return false; } },
        'Redirect URL must belong to apexmail.ee'
      ),
    });

    const parsed = schema.parse(body);

    const result = await ctx.stripe.createCheckoutSession(
      tenantId,
      parsed.priceId,
      parsed.successUrl,
      parsed.cancelUrl
    );

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Create portal session
  router.post('/portal', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      returnUrl: z.string().url().refine(
        (u) => { try { const h = new URL(u).hostname; return h.endsWith('apexmail.ee') || h === 'localhost'; } catch { return false; } },
        'Redirect URL must belong to apexmail.ee'
      ),
    });

    const parsed = schema.parse(body);

    const result = await ctx.stripe.createPortalSession(tenantId, parsed.returnUrl);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Get proration preview
  router.get('/proration/:planName', async (c) => {
    const tenantId = c.get('tenantId');
    const planName = c.req.param('planName');

    const result = await ctx.proration.previewProration(tenantId, planName);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ invoices: result.value });
  });

  // Get invoice details
  router.get('/invoices/:id', async (c) => {
    const invoiceId = c.req.param('id');
    const tenantId = c.get('tenantId');

    const result = await ctx.invoices.getInvoice(invoiceId);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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

    const result = await ctx.invoices.getInvoice(invoiceId);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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

    const result = await ctx.invoices.getInvoice(invoiceId);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Get wallet transactions
  router.get('/wallet/transactions', async (c) => {
    const tenantId = c.get('tenantId');
    const limit = Math.min(Math.max(parseInt(c.req.query('limit') ?? '50', 10) || 50, 1), 200);
    const offset = Math.max(parseInt(c.req.query('offset') ?? '0', 10) || 0, 0);
    const type = c.req.query('type') as 'credit' | 'debit' | undefined;

    const result = await ctx.wallet.getTransactions(tenantId, { limit, offset, type });

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ transactions: result.value });
  });

  // Get SLA credits
  router.get('/credits', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.slaCredits.getPendingCredits(tenantId);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value);
  });

  // Get dunning status
  router.get('/dunning', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.dunning.getFullState(tenantId);

    if (!result.ok) {
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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
      console.error("Billing operation failed:", result.error); return c.json({ error: "Operation failed" }, 500);
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
    const body = await c.req.json();

    const schema = z.object({
      emailsSent: z.number().min(0),
      apiCalls: z.number().min(0).optional().default(0),
    });

    const parsed = schema.parse(body);
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

  // Get PAYG current period usage and cost
  router.get('/payg/usage', async (c) => {
    const tenantId = c.get('tenantId');
    const now = new Date();
    const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    const usageResult = await ctx.metering.getUsage(tenantId, periodStart, periodEnd);

    if (!usageResult.ok) {
      console.error("Usage check failed:", usageResult.error); return c.json({ error: "Operation failed" }, 500);
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
    const body = await c.req.json();

    const schema = z.object({
      planName: z.string(),
      billingInterval: z.enum(['monthly', 'yearly']).optional().default('monthly'),
    });

    const parsed = schema.parse(body);

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
          console.error("Cancel failed:", cancelResult.error); return c.json({ error: "Operation failed" }, 500);
        }
      }

      // Update tenant plan to PAYG
      const updateResult = await ctx.plans.updateTenantPlan(tenantId, 'payg');

      if (!updateResult.ok) {
        console.error("Update failed:", updateResult.error); return c.json({ error: "Operation failed" }, 500);
      }

      // E-170: Audit trail for plan change to PAYG
      const previousSub = subscriptionResult.ok ? subscriptionResult.value : null;
      const effectiveDate = previousSub?.billingCycleEnd ?? new Date().toISOString();
      await ctx.db.query(
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

      return c.json({
        success: true,
        message: 'Switched to Pay As You Go billing',
        effectiveDate,
      });
    }

    // For regular plans, use proration service
    const previewResult = await ctx.proration.previewProration(tenantId, parsed.planName);

    if (!previewResult.ok) {
      console.error("Preview failed:", previewResult.error); return c.json({ error: "Operation failed" }, 500);
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
    await ctx.db.query(
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

    return c.json({
      success: true,
      proration: previewResult.value,
      newPlan: parsed.planName,
      billingInterval: parsed.billingInterval,
    });
  });

  return router;
}
