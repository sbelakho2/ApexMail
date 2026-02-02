/**
 * Admin Routes - Administrative billing endpoints
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { BillingEnv, BillingContext } from '../app.js';

export function adminRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  // Admin middleware
  router.use('*', async (c, next) => {
    const isAdmin = c.get('isAdmin');
    if (!isAdmin) {
      return c.json({ error: 'Admin access required' }, 403);
    }
    return next();
  });

  // List all tenants with billing status
  router.get('/tenants', async (c) => {
    const limit = parseInt(c.req.query('limit') ?? '50', 10);
    const offset = parseInt(c.req.query('offset') ?? '0', 10);
    const status = c.req.query('status');

    let query = `
      SELECT 
        t.id,
        t.name,
        t.created_at,
        s.status as subscription_status,
        s.current_period_end,
        p.name as plan_name,
        d.dunning_state,
        w.balance as wallet_balance
      FROM tenants t
      LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
      LEFT JOIN plans p ON s.plan_id = p.id
      LEFT JOIN dunning_states d ON t.id = d.tenant_id
      LEFT JOIN wallets w ON t.id = w.tenant_id
    `;

    const params: (string | number)[] = [];

    if (status) {
      query += ` WHERE s.status = $1`;
      params.push(status);
    }

    query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await ctx.db.query(query, params);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ tenants: result.value.rows, limit, offset });
  });

  // Get tenant billing details
  router.get('/tenants/:tenantId', async (c) => {
    const tenantId = c.req.param('tenantId');

    const [subscription, planLimits, dunning, wallet, invoices] = await Promise.all([
      ctx.stripe.getSubscription(tenantId),
      ctx.plans.getPlanLimits(tenantId),
      ctx.dunning.getFullState(tenantId),
      ctx.wallet.getBalance(tenantId),
      ctx.invoices.listInvoices(tenantId, { limit: 10 }),
    ]);

    return c.json({
      tenantId,
      subscription: subscription.ok ? subscription.value : null,
      plan: planLimits.ok ? planLimits.value : null,
      dunning: dunning.ok ? dunning.value : null,
      wallet: wallet.ok ? wallet.value : null,
      recentInvoices: invoices.ok ? invoices.value : [],
    });
  });

  // Apply credit to tenant
  router.post('/tenants/:tenantId/credits', async (c) => {
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      amount: z.number().positive(),
      reason: z.string(),
      expiresAt: z.string().datetime().optional(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');

    const result = await ctx.wallet.credit(
      tenantId,
      parsed.amount,
      `Admin credit: ${parsed.reason}`,
      `admin_credit_${adminId}_${Date.now()}`
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Override plan for tenant
  router.post('/tenants/:tenantId/plan-override', async (c) => {
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      planId: z.string(),
      reason: z.string(),
      expiresAt: z.string().datetime().optional(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');

    await ctx.db.query(
      `INSERT INTO plan_overrides (
        tenant_id, plan_id, reason, admin_id, expires_at, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (tenant_id) DO UPDATE SET
        plan_id = $2,
        reason = $3,
        admin_id = $4,
        expires_at = $5,
        updated_at = NOW()`,
      [
        tenantId,
        parsed.planId,
        parsed.reason,
        adminId,
        parsed.expiresAt ? new Date(parsed.expiresAt) : null,
      ]
    );

    return c.json({ success: true, message: 'Plan override applied' });
  });

  // Force subscription status
  router.post('/tenants/:tenantId/subscription-status', async (c) => {
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      status: z.enum(['active', 'past_due', 'canceled', 'suspended']),
      reason: z.string(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');

    await ctx.db.query(
      `UPDATE stripe_subscriptions 
       SET status = $2, admin_override_at = NOW(), admin_override_by = $3, admin_override_reason = $4
       WHERE tenant_id = $1`,
      [tenantId, parsed.status, adminId, parsed.reason]
    );

    // Log the action
    await ctx.db.query(
      `INSERT INTO billing_audit_log (
        tenant_id, action, actor_id, actor_type, details, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())`,
      [
        tenantId,
        'subscription_status_override',
        adminId,
        'admin',
        JSON.stringify({ newStatus: parsed.status, reason: parsed.reason }),
      ]
    );

    return c.json({ success: true, message: 'Subscription status updated' });
  });

  // Reset dunning state
  router.post('/tenants/:tenantId/dunning/reset', async (c) => {
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      reason: z.string(),
    });

    // Validate body even though we only need to log the reason
    schema.parse(body);
    
    // Reset dunning by recording a successful payment
    const result = await ctx.dunning.recordSuccessfulPayment(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ success: true, message: 'Dunning state reset' });
  });

  // Generate invoice for tenant
  router.post('/tenants/:tenantId/invoices', async (c) => {
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      periodStart: z.string().datetime(),
      periodEnd: z.string().datetime(),
      lineItems: z.array(z.object({
        description: z.string(),
        quantity: z.number(),
        unitPrice: z.number(),
      })),
      notes: z.string().optional(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.invoices.createInvoice({
      tenantId,
      periodStart: new Date(parsed.periodStart),
      periodEnd: new Date(parsed.periodEnd),
      lineItems: parsed.lineItems,
      notes: parsed.notes,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Get revenue report
  router.get('/reports/revenue', async (c) => {
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    if (!startDate || !endDate) {
      return c.json({ error: 'startDate and endDate required' }, 400);
    }

    const result = await ctx.db.query(
      `SELECT 
        DATE_TRUNC('day', paid_at) as date,
        SUM(total) as total_revenue,
        COUNT(*) as invoice_count,
        SUM(tax_amount) as total_tax,
        currency
      FROM invoices
      WHERE status = 'paid' AND paid_at >= $1 AND paid_at < $2
      GROUP BY DATE_TRUNC('day', paid_at), currency
      ORDER BY date`,
      [new Date(startDate), new Date(endDate)]
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get MRR report
  router.get('/reports/mrr', async (c) => {
    const result = await ctx.db.query(`
      SELECT 
        DATE_TRUNC('month', created_at) as month,
        COUNT(DISTINCT tenant_id) as active_subscriptions,
        SUM(
          CASE 
            WHEN billing_interval = 'month' THEN amount
            WHEN billing_interval = 'year' THEN amount / 12
            ELSE 0
          END
        ) as mrr
      FROM stripe_subscriptions
      WHERE status = 'active'
      GROUP BY DATE_TRUNC('month', created_at)
      ORDER BY month DESC
      LIMIT 12
    `);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get churn report
  router.get('/reports/churn', async (c) => {
    const result = await ctx.db.query(`
      SELECT 
        DATE_TRUNC('month', canceled_at) as month,
        COUNT(*) as churned_count,
        SUM(
          CASE 
            WHEN billing_interval = 'month' THEN amount
            WHEN billing_interval = 'year' THEN amount / 12
            ELSE 0
          END
        ) as churned_mrr,
        (
          SELECT COUNT(DISTINCT tenant_id)
          FROM stripe_subscriptions
          WHERE status = 'active' 
            AND created_at < DATE_TRUNC('month', s.canceled_at)
        ) as starting_count
      FROM stripe_subscriptions s
      WHERE status = 'canceled' AND canceled_at IS NOT NULL
      GROUP BY DATE_TRUNC('month', canceled_at)
      ORDER BY month DESC
      LIMIT 12
    `);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get dunning report
  router.get('/reports/dunning', async (c) => {
    const result = await ctx.db.query(`
      SELECT 
        dunning_state,
        COUNT(*) as tenant_count,
        SUM(amount_owed) as total_owed
      FROM dunning_states
      WHERE dunning_state != 'healthy'
      GROUP BY dunning_state
    `);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get cost report
  router.get('/reports/costs', async (c) => {
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    if (!startDate || !endDate) {
      return c.json({ error: 'startDate and endDate required' }, 400);
    }

    const result = await ctx.db.query(
      `SELECT 
        DATE_TRUNC('day', recorded_at) as date,
        SUM(storage_cost) as storage_cost,
        SUM(bandwidth_cost) as bandwidth_cost,
        SUM(compute_cost) as compute_cost,
        SUM(dedicated_ip_cost) as dedicated_ip_cost,
        SUM(total_cost) as total_cost,
        SUM(revenue) as revenue,
        (SUM(revenue) - SUM(total_cost)) / NULLIF(SUM(revenue), 0) * 100 as margin_percent
      FROM tenant_costs
      WHERE recorded_at >= $1 AND recorded_at < $2
      GROUP BY DATE_TRUNC('day', recorded_at)
      ORDER BY date`,
      [new Date(startDate), new Date(endDate)]
    );

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Export billing data
  router.get('/export', async (c) => {
    const type = c.req.query('type');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const format = c.req.query('format') ?? 'csv';

    if (!type || !startDate || !endDate) {
      return c.json({ error: 'type, startDate, and endDate required' }, 400);
    }

    let query: string;
    const params: Date[] = [new Date(startDate), new Date(endDate)];

    switch (type) {
      case 'invoices':
        query = `
          SELECT 
            i.invoice_number, i.tenant_id, t.name as tenant_name,
            i.subtotal, i.tax_amount, i.total, i.currency,
            i.status, i.issued_at, i.paid_at, i.due_date
          FROM invoices i
          JOIN tenants t ON i.tenant_id = t.id
          WHERE i.issued_at >= $1 AND i.issued_at < $2
          ORDER BY i.issued_at
        `;
        break;
      case 'subscriptions':
        query = `
          SELECT 
            s.tenant_id, t.name as tenant_name,
            p.name as plan_name, s.status,
            s.amount, s.currency, s.billing_interval,
            s.current_period_start, s.current_period_end,
            s.created_at, s.canceled_at
          FROM stripe_subscriptions s
          JOIN tenants t ON s.tenant_id = t.id
          JOIN plans p ON s.plan_id = p.id
          WHERE s.created_at >= $1 AND s.created_at < $2
          ORDER BY s.created_at
        `;
        break;
      case 'transactions':
        query = `
          SELECT 
            w.tenant_id, t.name as tenant_name,
            w.type, w.amount, w.balance_after,
            w.description, w.reference, w.created_at
          FROM wallet_transactions w
          JOIN tenants t ON w.tenant_id = t.id
          WHERE w.created_at >= $1 AND w.created_at < $2
          ORDER BY w.created_at
        `;
        break;
      default:
        return c.json({ error: 'Invalid export type' }, 400);
    }

    const result = await ctx.db.query(query, params);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (format === 'json') {
      return c.json({ data: result.value.rows });
    }

    // CSV format
    if (result.value.rows.length === 0) {
      return c.text('', 200, { 'Content-Type': 'text/csv' });
    }

    const headers = Object.keys(result.value.rows[0]!);
    const csvRows = [
      headers.join(','),
      ...result.value.rows.map((row: Record<string, unknown>) =>
        headers.map(h => {
          const val = row[h];
          if (val === null || val === undefined) return '';
          if (typeof val === 'string' && val.includes(',')) {
            return `"${val.replace(/"/g, '""')}"`;
          }
          return String(val);
        }).join(',')
      ),
    ];

    return c.text(csvRows.join('\n'), 200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="${type}_${startDate}_${endDate}.csv"`,
    });
  });

  return router;
}
