/**
 * Billing Routes - API endpoints for billing operations
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { BillingEnv, BillingContext } from '../app.js';

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
      return c.json({ error: result.error.message }, 500);
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
      return c.json({ error: result.error.message }, 500);
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
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Get subscription details
  router.get('/subscription', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.stripe.getSubscription(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
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
      successUrl: z.string().url(),
      cancelUrl: z.string().url(),
    });

    const parsed = schema.parse(body);

    const result = await ctx.stripe.createCheckoutSession(
      tenantId,
      parsed.priceId,
      parsed.successUrl,
      parsed.cancelUrl
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Create portal session
  router.post('/portal', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      returnUrl: z.string().url(),
    });

    const parsed = schema.parse(body);

    const result = await ctx.stripe.createPortalSession(tenantId, parsed.returnUrl);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Get proration preview
  router.get('/proration/:planName', async (c) => {
    const tenantId = c.get('tenantId');
    const planName = c.req.param('planName');

    const result = await ctx.proration.previewProration(tenantId, planName);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Get invoices
  router.get('/invoices', async (c) => {
    const tenantId = c.get('tenantId');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);

    const result = await ctx.invoices.listInvoices(tenantId, { limit, offset });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ invoices: result.value });
  });

  // Get invoice details
  router.get('/invoices/:id', async (c) => {
    const invoiceId = c.req.param('id');

    const result = await ctx.invoices.getInvoice(invoiceId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (!result.value) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    return c.json(result.value);
  });

  // Get invoice PDF
  router.get('/invoices/:id/pdf', async (c) => {
    const invoiceId = c.req.param('id');

    const result = await ctx.invoices.getInvoice(invoiceId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (!result.value) {
      return c.json({ error: 'Invoice not found' }, 404);
    }

    const pdfContent = ctx.invoices.generatePdfContent(result.value);

    return c.html(pdfContent);
  });

  // Get invoice e-Invoice XML
  router.get('/invoices/:id/xml', async (c) => {
    const invoiceId = c.req.param('id');

    const result = await ctx.invoices.getInvoice(invoiceId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (!result.value) {
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
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Get wallet transactions
  router.get('/wallet/transactions', async (c) => {
    const tenantId = c.get('tenantId');
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);
    const type = c.req.query('type') as 'credit' | 'debit' | undefined;

    const result = await ctx.wallet.getTransactions(tenantId, { limit, offset, type });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ transactions: result.value });
  });

  // Get SLA credits
  router.get('/credits', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.slaCredits.getPendingCredits(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Get dunning status
  router.get('/dunning', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.dunning.getFullState(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
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
      return c.json({ error: result.error.message }, 500);
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
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  return router;
}
